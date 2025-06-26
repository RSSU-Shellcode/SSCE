.code64

push {{.Reg.rax}}
mov {{.Reg.rax}}, {{.Reg.rbx}}
pop {{.Reg.rax}}
