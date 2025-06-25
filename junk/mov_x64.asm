.code64

push {{dr .Reg.rax}}
mov {{dr .Reg.rax}}, {{dr .Reg.rbx}}
pop {{dr .Reg.rax}}
