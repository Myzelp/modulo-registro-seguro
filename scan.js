// scan.js
const { ESLint } = require("eslint");
const fs = require("fs");

async function scanFile(filePath) {
    console.log(`\nAnalizando: ${filePath}`);
    console.log("=".repeat(50));
    
    try {
        // Crear instancia de ESLint sin opciones (usará .eslintrc.json automáticamente)
        const eslint = new ESLint();
        
        const results = await eslint.lintFiles([filePath]);
        
        if (results.length === 0) {
            console.log("No se encontraron resultados");
            return;
        }
        
        const result = results[0];
        
        if (result.errorCount === 0 && result.warningCount === 0) {
            console.log("\nNo se encontraron problemas de seguridad.");
            return;
        }
        
        if (result.errorCount > 0) {
            console.log(`\n${result.errorCount} ERRORES encontrados:`);
            console.log("-".repeat(40));
            result.messages
                .filter(m => m.severity === 2)
                .forEach((msg, idx) => {
                    console.log(`\n[${idx + 1}] ${msg.ruleId || "Regla desconocida"}`);
                    console.log(`    Linea: ${msg.line}`);
                    console.log(`    Mensaje: ${msg.message}`);
                });
        }
        
        if (result.warningCount > 0) {
            console.log(`\n${result.warningCount} ADVERTENCIAS encontradas:`);
            console.log("-".repeat(40));
            result.messages
                .filter(m => m.severity === 1)
                .forEach((msg, idx) => {
                    console.log(`\n[${idx + 1}] ${msg.ruleId || "Regla desconocida"}`);
                    console.log(`    Linea: ${msg.line}`);
                    console.log(`    Mensaje: ${msg.message}`);
                });
        }
        
        return result;
        
    } catch (error) {
        console.error(`Error analizando ${filePath}:`, error.message);
        return null;
    }
}

async function main() {
    console.log("INICIANDO ANALISIS DE SEGURIDAD CON ESLint");
    console.log("=".repeat(50));
    
    const filesToScan = ["./server.js"];
    
    for (const file of filesToScan) {
        if (fs.existsSync(file)) {
            await scanFile(file);
        } else {
            console.log(`\nArchivo no encontrado: ${file}`);
        }
    }
    
    console.log("\nAnalisis completado");
}

main().catch(console.error);