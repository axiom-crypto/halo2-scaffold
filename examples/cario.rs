use clap::Parser;
use halo2_base::gates::{GateChip, GateInstructions};
use halo2_base::utils::{fe_to_biguint, ScalarField};
use halo2_base::QuantumCell;
use halo2_base::{
    AssignedValue, Context, QuantumCell::Constant, QuantumCell::Existing, QuantumCell::Witness,
};
use halo2_scaffold::scaffold::cmd::Cli;
use halo2_scaffold::scaffold::run;
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CarioState {
    pub memory: Vec<String>,
    pub pc: String,
    pub ap: String,
    pub fp: String,
}

#[derive(Clone, Copy, Debug)]
pub struct DecodedInstruction<F: ScalarField> {
    off_dst: AssignedValue<F>,
    off_op0: AssignedValue<F>,
    off_op1: AssignedValue<F>,
    dst_reg: AssignedValue<F>,
    op0_reg: AssignedValue<F>,
    op1_src: AssignedValue<F>,
    res_logic: AssignedValue<F>,
    pc_update: AssignedValue<F>,
    ap_update: AssignedValue<F>,
    op_code: AssignedValue<F>,
}

fn bit_slice<F: ScalarField>(
    ctx: &mut Context<F>,
    gate: &GateChip<F>,
    bits: &Vec<AssignedValue<F>>,
    start: usize,
    end: usize,
) -> AssignedValue<F> {
    gate.inner_product(
        ctx,
        (&bits[start..end]).to_vec(),
        (0..(end - start)).map(|i| Constant(gate.pow_of_two[i])),
    )
}

// recenter a value within [0, 2^16) to [-2^15, 2^15)
// since the sub here might overflow, the correctness of our circuit relies on any subsequent operations with bias always give positive result
// e.g. ap + off_op0 >= 0
fn bias<F: ScalarField>(
    ctx: &mut Context<F>,
    gate: &GateChip<F>,
    input: AssignedValue<F>,
) -> AssignedValue<F> {
    gate.sub(ctx, input, Constant(F::from(2u64.pow(15u32))))
}

fn decode_instruction<F: ScalarField>(
    ctx: &mut Context<F>,
    gate: &GateChip<F>,
    instruction: AssignedValue<F>,
) -> DecodedInstruction<F> {
    let instruction_bits = gate.num_to_bits(ctx, instruction, 63);
    let off_dst_raw = bit_slice(ctx, gate, &instruction_bits, 0, 16);
    let off_dst = bias(ctx, gate, off_dst_raw);
    let off_op0_raw = bit_slice(ctx, gate, &instruction_bits, 16, 32);
    let off_op0 = bias(ctx, gate, off_op0_raw);
    let off_op1_raw = bit_slice(ctx, gate, &instruction_bits, 32, 48);
    let off_op1 = bias(ctx, gate, off_op1_raw);
    let dst_reg = instruction_bits[48];
    let op0_reg = instruction_bits[49];
    let op1_src = bit_slice(ctx, gate, &instruction_bits, 50, 53);
    let res_logic = bit_slice(ctx, gate, &instruction_bits, 53, 55);
    let pc_update = bit_slice(ctx, gate, &instruction_bits, 55, 58);
    let ap_update = bit_slice(ctx, gate, &instruction_bits, 58, 60);
    let op_code = bit_slice(ctx, gate, &instruction_bits, 60, 63);

    DecodedInstruction {
        off_dst,
        off_op0,
        off_op1,
        dst_reg,
        op0_reg,
        op1_src,
        res_logic,
        pc_update,
        ap_update,
        op_code,
    }
}

// todo: read memory through dynamic look up table
fn read_memory<F: ScalarField>(
    ctx: &mut Context<F>,
    gate: &GateChip<F>,
    memory: Vec<AssignedValue<F>>,
    address: AssignedValue<F>,
) -> AssignedValue<F> {
    gate.select_from_idx(ctx, memory, address)
}

fn compute_op0<F: ScalarField>(
    ctx: &mut Context<F>,
    gate: &GateChip<F>,
    memory: Vec<AssignedValue<F>>,
    op0_reg: AssignedValue<F>, // one bit
    ap: AssignedValue<F>,
    fp: AssignedValue<F>,
    off_op0: AssignedValue<F>,
) -> AssignedValue<F> {
    let ap_plus_off_op0 = gate.add(ctx, ap, off_op0);
    let fp_plus_off_op0 = gate.add(ctx, fp, off_op0);
    let op0_0 = read_memory(ctx, gate, memory.clone(), ap_plus_off_op0);
    let op_0_1 = read_memory(ctx, gate, memory.clone(), fp_plus_off_op0);
    let op0 = gate.select(ctx, op_0_1, op0_0, op0_reg);
    op0
}

// todo: is undefined behavior handled properly?
fn compute_op1_and_instruction_size<F: ScalarField>(
    ctx: &mut Context<F>,
    gate: &GateChip<F>,
    memory: Vec<AssignedValue<F>>,
    op1_src: AssignedValue<F>,
    op0: AssignedValue<F>,
    off_op1: AssignedValue<F>,
    fp: AssignedValue<F>,
    ap: AssignedValue<F>,
    pc: AssignedValue<F>,
) -> (AssignedValue<F>, AssignedValue<F>) {
    //op1_src != 3
    assert!(fe_to_biguint(op1_src.value()) != 3u64.into());
    assert!(fe_to_biguint(op1_src.value()) <= 4u64.into());

    let op0_off_op1 = gate.add(ctx, op0, off_op1);
    let pc_off_op1 = gate.add(ctx, pc, off_op1);
    let fp_off_op1 = gate.add(ctx, fp, off_op1);
    let ap_off_op1 = gate.add(ctx, ap, off_op1);

    let op1_values: Vec<QuantumCell<F>> = vec![
        Existing(read_memory(ctx, gate, memory.clone(), op0_off_op1)),
        Existing(read_memory(ctx, gate, memory.clone(), pc_off_op1)),
        Existing(read_memory(ctx, gate, memory.clone(), fp_off_op1)),
        Witness(F::zero()), // undefined behavior
        Existing(read_memory(ctx, gate, memory.clone(), ap_off_op1)),
    ];
    let instruction_values = vec![
        Constant(F::one()),
        Constant(F::from(2u64)),
        Constant(F::one()),
        Witness(F::zero()), // undefined behavior
        Constant(F::one()),
    ];

    let op1 = gate.select_from_idx(ctx, op1_values, op1_src);
    let instruction_size = gate.select_from_idx(ctx, instruction_values, op1_src);
    (op1, instruction_size)
}

fn compute_res<F: ScalarField>(
    ctx: &mut Context<F>,
    gate: &GateChip<F>,
    pc_update: AssignedValue<F>,
    res_logic: AssignedValue<F>,
    op1: AssignedValue<F>,
    op0: AssignedValue<F>,
) -> AssignedValue<F> {
    assert!(fe_to_biguint(pc_update.value()) != 3u64.into());
    assert!(fe_to_biguint(pc_update.value()) <= 4u64.into());
    assert!(fe_to_biguint(res_logic.value()) <= 2u64.into());

    let op1_op0 = gate.add(ctx, op1, op0);
    let op1_mul_op0 = gate.mul(ctx, op1, op0);
    let case_0_1_2_value =
        Existing(gate.select_from_idx(ctx, vec![op1, op1_op0, op1_mul_op0], res_logic));
    let res_values = [
        case_0_1_2_value,
        case_0_1_2_value,
        case_0_1_2_value,
        Witness(F::zero()), // undefined behavior
        Witness(F::zero()), // undefined behavior
    ];
    let res = gate.select_from_idx(ctx, res_values, pc_update);
    res
}

fn compute_dst<F: ScalarField>(
    ctx: &mut Context<F>,
    gate: &GateChip<F>,
    memory: Vec<AssignedValue<F>>,
    ap: AssignedValue<F>,
    fp: AssignedValue<F>,
    off_dst: AssignedValue<F>,
    dst_reg: AssignedValue<F>,
) -> AssignedValue<F> {
    let is_dst_reg_zero = gate.is_zero(ctx, dst_reg);
    let address_a = gate.add(ctx, ap, off_dst);
    let var_a = read_memory(ctx, gate, memory.clone(), address_a);
    let address_b = gate.add(ctx, fp, off_dst);
    let var_b = read_memory(ctx, gate, memory.clone(), address_b);
    let dst = gate.select(ctx, var_a, var_b, is_dst_reg_zero);
    dst
}

fn compute_next_pc<F: ScalarField>(
    ctx: &mut Context<F>,
    gate: &GateChip<F>,
    pc: AssignedValue<F>,
    instruction_size: AssignedValue<F>,
    res: AssignedValue<F>,
    dst: AssignedValue<F>,
    op1: AssignedValue<F>,
    pc_update: AssignedValue<F>,
) -> AssignedValue<F> {
    assert!(fe_to_biguint(pc_update.value()) != 3u64.into());
    assert!(fe_to_biguint(pc_update.value()) <= 4u64.into());

    let var_a = gate.add(ctx, pc, instruction_size);
    let var_b = gate.add(ctx, pc, op1);
    let sel = gate.is_zero(ctx, dst);
    let case_4_value = gate.select(ctx, var_a, var_b, sel);
    let next_pc_values = vec![
        Existing(gate.add(ctx, pc, instruction_size)),
        Existing(res),
        Existing(gate.add(ctx, pc, res)),
        Witness(F::zero()), // undefined behavior
        Existing(case_4_value),
    ];
    let next_pc = gate.select_from_idx(ctx, next_pc_values, pc_update);
    next_pc
}

fn compute_next_ap_fp<F: ScalarField>(
    ctx: &mut Context<F>,
    gate: &GateChip<F>,
    op_code: AssignedValue<F>,
    pc: AssignedValue<F>,
    instruction_size: AssignedValue<F>,
    res: AssignedValue<F>,
    dst: AssignedValue<F>,
    op0: AssignedValue<F>,
    fp: AssignedValue<F>,
    ap: AssignedValue<F>,
    ap_update: AssignedValue<F>,
) -> (AssignedValue<F>, AssignedValue<F>) {
    assert!(fe_to_biguint(ap_update.value()) <= 2u64.into());
    assert!(fe_to_biguint(op_code.value()) <= 4u64.into());
    assert!(fe_to_biguint(op_code.value()) != 3u64.into());
    // first, implement assertions
    // if opcode == 1, op0 == pc + instruction_size
    let mut condition = gate.is_equal(ctx, op_code, Constant(F::one()));
    let sub_b = gate.add(ctx, pc, instruction_size);
    let mul_b = gate.sub(ctx, op0, sub_b);
    let value_to_check_1 = gate.mul(ctx, condition, mul_b);
    gate.assert_is_const(ctx, &value_to_check_1, &F::zero());
    // if opcode == 1, dst == fp
    let mul_b_2 = gate.sub(ctx, dst, fp);
    let value_to_check_2 = gate.mul(ctx, condition, mul_b_2);
    gate.assert_is_const(ctx, &value_to_check_2, &F::zero());

    // if opcode == 4, res = dst
    condition = gate.is_equal(ctx, op_code, Constant(F::from(4u64)));
    let mul_b_3 = gate.sub(ctx, res, dst);
    let value_to_check_3 = gate.mul(ctx, condition, mul_b_3);
    gate.assert_is_const(ctx, &value_to_check_3, &F::zero());

    // compute next_ap
    let next_ap_value_1 = gate.add(ctx, ap, res);
    let next_ap_value_2 = gate.add(ctx, ap, Constant(F::one()));
    let next_ap_swtich_by_ap_update_0_2_4 =
        gate.select_from_idx(ctx, vec![ap, next_ap_value_1, next_ap_value_2], ap_update);
    let var_a = gate.add(ctx, ap, Constant(F::from(2u64)));
    let sel = gate.is_zero(ctx, ap_update);
    let next_ap_swtich_by_ap_update_1 = gate.select(
        ctx,
        var_a,
        Witness(F::zero()), // undefined behavior
        sel,
    );
    let next_ap_values = [
        Existing(next_ap_swtich_by_ap_update_0_2_4),
        Existing(next_ap_swtich_by_ap_update_1),
        Existing(next_ap_swtich_by_ap_update_0_2_4),
        Witness(F::zero()), // undefined behavior
        Existing(next_ap_swtich_by_ap_update_0_2_4),
    ];
    let next_ap = gate.select_from_idx(ctx, next_ap_values, op_code);

    // compute next_fp
    let next_fp_values = [
        Existing(fp),
        Existing(gate.add(ctx, ap, Constant(F::from(2u64)))),
        Existing(dst),
        Witness(F::zero()),
        Existing(fp),
    ];
    let next_fp = gate.select_from_idx(ctx, next_fp_values, op_code);

    (next_ap, next_fp)
}

fn state_transition<F: ScalarField>(
    ctx: &mut Context<F>,
    memory: Vec<AssignedValue<F>>,
    pc: AssignedValue<F>,
    ap: AssignedValue<F>,
    fp: AssignedValue<F>,
) -> (AssignedValue<F>, AssignedValue<F>, AssignedValue<F>) {
    let gate = GateChip::<F>::default();

    let instruction = gate.select_from_idx(ctx, memory.to_vec(), pc);
    let decoded_instruction = decode_instruction(ctx, &gate, instruction);
    let op0 = compute_op0(
        ctx,
        &gate,
        memory.clone(),
        decoded_instruction.op0_reg,
        ap,
        fp,
        decoded_instruction.off_op0,
    );
    let (op1, instruction_size) = compute_op1_and_instruction_size(
        ctx,
        &gate,
        memory.clone(),
        decoded_instruction.op1_src,
        op0,
        decoded_instruction.off_op1,
        fp,
        ap,
        pc,
    );
    let res = compute_res(
        ctx,
        &gate,
        decoded_instruction.pc_update,
        decoded_instruction.res_logic,
        op1,
        op0,
    );
    let dst = compute_dst(
        ctx,
        &gate,
        memory.clone(),
        ap,
        fp,
        decoded_instruction.off_dst,
        decoded_instruction.dst_reg,
    );
    let next_pc = compute_next_pc(
        ctx,
        &gate,
        pc,
        instruction_size,
        res,
        dst,
        op1,
        decoded_instruction.pc_update,
    );
    let (next_ap, next_fp) = compute_next_ap_fp(
        ctx,
        &gate,
        decoded_instruction.op_code,
        pc,
        instruction_size,
        res,
        dst,
        op0,
        fp,
        ap,
        decoded_instruction.ap_update,
    );
    (next_pc, next_ap, next_fp)
}

fn vm<F: ScalarField>(
    ctx: &mut Context<F>,
    cario_state: CarioState,
    _: &mut Vec<AssignedValue<F>>,
) {
    let num_clock_cycles = 10;
    let mut fp = ctx.load_witness(F::from_str_vartime(&cario_state.fp).unwrap());
    let mut ap = ctx.load_witness(F::from_str_vartime(&cario_state.ap).unwrap());
    let mut pc = ctx.load_witness(F::from_str_vartime(&cario_state.pc).unwrap());
    let memory = ctx.assign_witnesses(
        cario_state.memory.iter().map(|x| F::from_str_vartime(x).unwrap()).collect::<Vec<_>>(),
    );
    for _ in 0..num_clock_cycles {
        (pc, ap, fp) = state_transition(ctx, memory.clone(), pc, ap, fp);
    }
}

fn main() {
    env_logger::init();

    let args = Cli::parse();

    run(vm, args);
}
