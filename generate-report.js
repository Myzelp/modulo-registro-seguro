// generate-report.js
const { ESLint } = require("eslint");
const fs = require("fs");

async function generateHTMLReport() {
    console.log("Generando reporte de seguridad HTML...");
    
    const filePath = "./server.js";
    
    if (!fs.existsSync(filePath)) {
        console.error(`Archivo ${filePath} no encontrado`);
        process.exit(1);
    }
    
    try {
        const eslint = new ESLint();
        const results = await eslint.lintFiles([filePath]);
        
        if (results.length === 0) {
            console.log("No se obtuvieron resultados");
            return;
        }
        
        const result = results[0];
        
        const errors = result.messages.filter(m => m.severity === 2);
        const warnings = result.messages.filter(m => m.severity === 1);
        
        const html = `<!DOCTYPE html>
<html lang="es">
<head>
    <meta charset="UTF-8">
    <title>Reporte de Seguridad - ESLint SAST</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body { 
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; 
            background: #1e1e2e;
            min-height: 100vh;
            padding: 20px;
        }
        .container { 
            max-width: 1200px; 
            margin: 0 auto; 
            background: white; 
            border-radius: 8px; 
            box-shadow: 0 4px 6px rgba(0,0,0,0.1);
            overflow: hidden;
        }
        .header { 
            background: #2c3e50;
            color: white; 
            padding: 30px; 
        }
        .header h1 { font-size: 24px; margin-bottom: 10px; }
        .header p { opacity: 0.9; font-size: 14px; }
        .summary {
            display: grid;
            grid-template-columns: repeat(3, 1fr);
            gap: 20px;
            padding: 30px;
            background: #f8f9fa;
        }
        .summary-card {
            background: white;
            padding: 20px;
            border-radius: 8px;
            text-align: center;
            box-shadow: 0 1px 3px rgba(0,0,0,0.1);
        }
        .summary-card h3 { font-size: 14px; color: #6c757d; margin-bottom: 10px; }
        .summary-card .number { font-size: 48px; font-weight: bold; }
        .summary-card.errors .number { color: #dc3545; }
        .summary-card.warnings .number { color: #ffc107; }
        .summary-card.total .number { color: #17a2b8; }
        .content { padding: 30px; }
        .vulnerability {
            border: 1px solid #e9ecef;
            border-radius: 8px;
            margin-bottom: 20px;
            overflow: hidden;
        }
        .vuln-header {
            padding: 15px 20px;
            display: flex;
            justify-content: space-between;
            align-items: center;
            background: #f8f9fa;
            border-bottom: 1px solid #e9ecef;
        }
        .severity-badge {
            display: inline-block;
            padding: 4px 12px;
            border-radius: 20px;
            font-size: 12px;
            font-weight: bold;
            color: white;
        }
        .severity-error { background: #dc3545; }
        .severity-warning { background: #ffc107; color: #333; }
        .vuln-body { padding: 20px; background: white; }
        .info-grid {
            display: grid;
            grid-template-columns: 100px 1fr;
            gap: 10px;
            margin-top: 10px;
        }
        .info-label { font-weight: bold; color: #495057; }
        table {
            width: 100%;
            border-collapse: collapse;
            margin-top: 20px;
        }
        th, td {
            border: 1px solid #dee2e6;
            padding: 12px;
            text-align: left;
        }
        th {
            background: #2c3e50;
            color: white;
        }
        tr:nth-child(even) { background: #f8f9fa; }
        footer {
            background: #f8f9fa;
            padding: 20px;
            text-align: center;
            color: #6c757d;
            border-top: 1px solid #e9ecef;
            font-size: 12px;
        }
        .success-box {
            background: #d4edda;
            color: #155724;
            padding: 30px;
            border-radius: 8px;
            text-align: center;
            margin: 20px 0;
        }
        .success-box h2 { margin-bottom: 10px; font-size: 20px; }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>Reporte de Seguridad - SAST con ESLint</h1>
            <p>Analisis Estatico de Seguridad para Node.js</p>
            <p>Fecha: ${new Date().toLocaleString()}</p>
            <p>Archivo analizado: server.js</p>
        </div>
        
        <div class="summary">
            <div class="summary-card errors">
                <h3>ERRORES</h3>
                <div class="number">${errors.length}</div>
                <small>Requieren correccion inmediata</small>
            </div>
            <div class="summary-card warnings">
                <h3>ADVERTENCIAS</h3>
                <div class="number">${warnings.length}</div>
                <small>Recomendable corregir</small>
            </div>
            <div class="summary-card total">
                <h3>TOTAL</h3>
                <div class="number">${result.messages.length}</div>
                <small>Problemas encontrados</small>
            </div>
        </div>
        
        <div class="content">
            ${result.messages.length === 0 ? `
            <div class="success-box">
                <h2>No se encontraron vulnerabilidades de seguridad</h2>
                <p>Tu codigo cumple con las buenas practicas de seguridad.</p>
            </div>
            ` : `
            <h2>Detalle de Vulnerabilidades</h2>
            ${result.messages.map((msg, idx) => `
            <div class="vulnerability">
                <div class="vuln-header">
                    <div>
                        <strong>${msg.ruleId || "Regla desconocida"}</strong>
                    </div>
                    <span class="severity-badge severity-${msg.severity === 2 ? 'error' : 'warning'}">
                        ${msg.severity === 2 ? 'ERROR' : 'ADVERTENCIA'}
                    </span>
                </div>
                <div class="vuln-body">
                    <div class="info-grid">
                        <div class="info-label">Mensaje:</div>
                        <div>${msg.message}</div>
                        <div class="info-label">Ubicacion:</div>
                        <div>Linea ${msg.line}, Columna ${msg.column}</div>
                        <div class="info-label">Severidad:</div>
                        <div>${msg.severity === 2 ? 'Alta - Corregir inmediatamente' : 'Media - Recomendable corregir'}</div>
                    </div>
                </div>
            </div>
            `).join('')}
            
            <h2 style="margin-top: 40px;">Guia de Correccion</h2>
            <table>
                <thead>
                    <tr><th>Regla</th><th>Solucion</th></tr>
                </thead>
                <tbody>
                    <tr>
                        <td><code>no-eval</code> / <code>no-implied-eval</code></code></td>
                        <td>Nunca usar eval() o setTimeout con strings. Usar JSON.parse() para datos JSON.</td>
                    </tr>
                    <tr>
                        <td><code>no-new-func</code></code></td>
                        <td>Evitar el constructor Function() que es equivalente a eval()</td>
                    </tr>
                    <tr>
                        <td><code>no-script-url</code></code></td>
                        <td>No usar javascript: en URLs, puede ejecutar codigo malicioso</td>
                    </tr>
                    <tr>
                        <td><code>no-unsafe-finally</code></code></td>
                        <td>No usar return, throw, break dentro de bloques finally</td>
                    </tr>
                </tbody>
            </table>
            `}
        </div>
        
        <footer>
            <p>Herramienta: ESLint | Proyecto: Modulo Registro Seguro</p>
        </footer>
    </div>
</body>
</html>`;
        
        fs.writeFileSync("./reporte_seguridad.html", html);
        console.log("\nReporte HTML generado: reporte_seguridad.html");
        console.log(`Resumen: ${result.errorCount} errores, ${result.warningCount} advertencias`);
        
    } catch (error) {
        console.error("Error generando reporte:", error.message);
        process.exit(1);
    }
}

generateHTMLReport();