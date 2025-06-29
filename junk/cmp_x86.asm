.code32

pushfd

cmp {{.Reg.eax}}, {{.Reg.ebx}}

popfd
