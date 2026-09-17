# Sin protecciones a proposito. En un binario real muchas de estas estan
# activadas, y por eso las cadenas de formato son dificiles de explotar hoy.
# Se activan una por una en los ejercicios del final, para que se vea el efecto.
CFLAGS = -m32 -fno-stack-protector -no-pie -z norelro -Wno-format-security

vuln: vuln.c
	gcc $(CFLAGS) -o vuln vuln.c
	@echo "  listo. corre:  ./vuln"

duro: vuln.c
	gcc -m32 -fstack-protector-all -pie -z relro -z now -D_FORTIFY_SOURCE=2 -O2 -o vuln_duro vuln.c
	@echo "  version endurecida. probá los mismos ataques y mirá que cambia."

limpiar:
	rm -f vuln vuln_duro
