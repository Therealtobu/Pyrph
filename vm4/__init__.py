"""
vm4 – Fragment Graph Execution Engine (VM4)

4 layers:
  L1: Fragment Graph     – xóa khái niệm instruction
  L2: Execution Fabric   – scheduler non-deterministic nhưng hội tụ
  L3: State Mesh         – không có register/value thật
  L4: Output Reconstruction + DNA Lock

Không có opcode. Không có instruction list.
Không có điểm nào chứa giá trị thật.
Chỉ khi FG + Fabric + Mesh + DNA hội tụ đúng nhịp → result.
"""
