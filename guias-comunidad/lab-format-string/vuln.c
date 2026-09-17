/* Laboratorio de cadenas de formato.
 *
 * Programa DELIBERADAMENTE vulnerable, para romperlo cuantas veces quieras.
 * El fallo es una sola linea, y es el mismo que aparece en software real:
 *
 *     printf(entrada)      en vez de     printf("%s", entrada)
 *
 * Cuando printf recibe tu texto como FORMATO en vez de como DATO, cada %x, %s
 * o %n que escribas son instrucciones que printf obedece. Ahi empieza todo.
 *
 * Compilar:  make
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* El objetivo de los niveles 3 y 4. Empieza en 0; hay que ponerlo en 0x1337. */
int cerradura = 0;

/* El objetivo del nivel 5: una funcion que NADIE llama. */
void premio(void) {
    puts("\n  *** Conseguiste ejecutar premio(). Eso es control del flujo. ***");
    FILE *f = fopen("flag.txt", "r");
    if (f) { char b[64] = {0}; fgets(b, 63, f); printf("  %s\n", b); fclose(f); }
    else   { puts("  (no hay flag.txt, pero llegaste)"); }
    exit(0);
}

int main(int argc, char **argv) {
    char entrada[256];
    char secreto[32] = "SECRETO_EN_LA_PILA";

    puts("=== laboratorio de cadenas de formato ===");
    printf("  cerradura esta en %p y vale 0x%x\n", (void *)&cerradura, cerradura);
    printf("  premio() esta en  %p\n", (void *)&premio);
    puts("  escribe algo (Ctrl+D para salir):\n");

    while (fgets(entrada, sizeof(entrada), stdin)) {
        entrada[strcspn(entrada, "\n")] = 0;

        printf("  dijiste: ");
        printf(entrada);          /* <<<<<<  AQUI ESTA EL FALLO  */
        printf("\n");

        if (cerradura == 0x1337) {
            puts("  *** cerradura abierta. Nivel superado. ***");
            exit(0);
        }
        printf("\n  escribe algo:\n");
    }
    /* secreto nunca se imprime: hay que sacarlo de la pila */
    (void)secreto; (void)argc; (void)argv;
    return 0;
}
