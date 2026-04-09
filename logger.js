// logger.js
const winston = require('winston');
const DailyRotateFile = require('winston-daily-rotate-file');
const path = require('path');

// Configuración del formato personalizado
const logFormat = winston.format.printf(({ timestamp, level, message }) => {
    return `[${timestamp}] | [${level.toUpperCase()}] | ${message}`;
});

// Configuración del transport para archivo rotativo diario
const dailyRotateTransport = new DailyRotateFile({
    filename: path.join(__dirname, 'logs', 'app-%DATE%.log'),
    datePattern: 'YYYY-MM-DD',
    maxSize: '20m',
    maxFiles: '14d',
    format: winston.format.combine(
        winston.format.timestamp({ format: 'YYYY-MM-DD HH:mm:ss' }),
        logFormat
    )
});

// Transport para consola (opcional, para desarrollo)
const consoleTransport = new winston.transports.Console({
    format: winston.format.combine(
        winston.format.colorize(),
        winston.format.timestamp({ format: 'YYYY-MM-DD HH:mm:ss' }),
        logFormat
    )
});

// Crear el logger
const logger = winston.createLogger({
    level: 'debug',
    transports: [
        dailyRotateTransport,
        // consoleTransport // Descomentar si quieres ver logs también en consola
    ]
});

// Filtro de seguridad para datos sensibles
function sanitizeMessage(message) {
    // Reemplazar posibles contraseñas en texto plano
    let sanitized = message.replace(/contraseña["']?\s*:\s*["'][^"']*["']/gi, 'contraseña: "***"');
    sanitized = sanitized.replace(/password["']?\s*:\s*["'][^"']*["']/gi, 'password: "***"');
    sanitized = sanitized.replace(/oldPassword["']?\s*:\s*["'][^"']*["']/gi, 'oldPassword: "***"');
    sanitized = sanitized.replace(/newPassword["']?\s*:\s*["'][^"']*["']/gi, 'newPassword: "***"');
    
    // Reemplazar tokens JWT completos (solo mostrar primeros 20 caracteres)
    sanitized = sanitized.replace(/token["']?\s*:\s*["'][A-Za-z0-9-_=]+\.[A-Za-z0-9-_=]+\.[A-Za-z0-9-_.+=]*["']/gi, (match) => {
        const tokenMatch = match.match(/["']([A-Za-z0-9-_=]+\.[A-Za-z0-9-_=]+\.[A-Za-z0-9-_.+=]*)["']/);
        if (tokenMatch) {
            const token = tokenMatch[1];
            const truncatedToken = token.substring(0, 20) + '...[TRUNCATED]';
            return match.replace(token, truncatedToken);
        }
        return match;
    });
    
    // Reemplazar emails (mostrar solo dominio, no usuario completo)
    sanitized = sanitized.replace(/\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b/g, (email) => {
        const parts = email.split('@');
        if (parts.length === 2) {
            const maskedUser = parts[0].substring(0, 2) + '...';
            return `${maskedUser}@${parts[1]}`;
        }
        return email;
    });
    
    return sanitized;
}

// Wrapper para sanitizar automáticamente
const secureLogger = {
    debug: (message) => logger.debug(sanitizeMessage(message)),
    info: (message) => logger.info(sanitizeMessage(message)),
    warning: (message) => logger.warning(sanitizeMessage(message)),
    error: (message) => logger.error(sanitizeMessage(message)),
    critical: (message) => logger.critical(sanitizeMessage(message))
};

module.exports = secureLogger;