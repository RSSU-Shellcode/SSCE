.code32

push {{.Reg.eax}}

{{if .Switch.A}}
mov {{.Reg.eax}}, {{.Reg.ebx}}
{{end}}

{{if .Switch.B}}
xor {{.Reg.eax}}, {{.Reg.ecx}}
{{end}}

{{if .Switch.C}}
xor {{.Reg.eax}}, {{.DWORD.D}}
{{end}}

{{if .Switch.D}}
mov {{.Reg.eax}}, {{.WORD.E}}
{{end}}

{{if .Switch.E}}
ror {{.Reg.eax}}, {{.Less32.A}}
xor {{.Reg.eax}}, {{.Reg.edi}}
rol {{.Reg.eax}}, {{.Less32.B}}
{{end}}

pop {{.Reg.eax}}

