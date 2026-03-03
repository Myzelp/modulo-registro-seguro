# jwt_handler.py
import jwt
import sys
import json
import datetime
import os

SECRET_KEY = "tu-clave-secreta-super-segura-2024"  # Cambia esto por una clave segura

def generar_token(payload):
    """Genera un token JWT con expiración de 1 hora"""
    # Añadir tiempo de expiración al payload
    payload['exp'] = datetime.datetime.utcnow() + datetime.timedelta(hours=1)
    payload['iat'] = datetime.datetime.utcnow()  # Issued at
    
    token = jwt.encode(payload, SECRET_KEY, algorithm='HS256')
    return token

def verificar_token(token):
    """Verifica y decodifica un token JWT"""
    try:
        decoded = jwt.decode(token, SECRET_KEY, algorithms=['HS256'])
        return {"valido": True, "payload": decoded}
    except jwt.ExpiredSignatureError:
        return {"valido": False, "error": "Token expirado"}
    except jwt.InvalidTokenError:
        return {"valido": False, "error": "Token inválido"}

def main():
    # Verificar que nos pasaron el nombre del archivo
    if len(sys.argv) < 2:
        print(json.dumps({"error": "Se requiere: nombre del archivo temporal"}))
        return
    
    archivo_temporal = sys.argv[1]
    print(f"Leyendo archivo: {archivo_temporal}", file=sys.stderr)
    
    try:
        # Leer los datos del archivo temporal
        with open(archivo_temporal, 'r') as f:
            datos = json.load(f)
        
        print(f"Datos leídos: {datos}", file=sys.stderr)
        
        # Obtener la acción y los datos
        action = datos.get('action')
        
        if action == "generar":
            payload = datos.get('payload')
            print(f"Generando token para payload: {payload}", file=sys.stderr)
            
            try:
                token = generar_token(payload)
                print(f"Token generado: {token[:20]}...", file=sys.stderr)
                # IMPORTANTE: Imprimimos SOLO el token, sin JSON
                print(token)
            except Exception as e:
                print(json.dumps({"error": f"Error generando token: {str(e)}"}), file=sys.stderr)
                print(json.dumps({"error": str(e)}))
        
        elif action == "verificar":
            token = datos.get('token')
            print(f"Verificando token: {token[:20]}...", file=sys.stderr)
            
            try:
                resultado = verificar_token(token)
                print(f"Resultado verificación: {resultado}", file=sys.stderr)
                print(json.dumps(resultado))
            except Exception as e:
                print(json.dumps({"error": f"Error verificando token: {str(e)}"}))
        
        else:
            print(json.dumps({"error": f"Acción no válida: {action}"}))
            
        # Limpiar el archivo temporal (opcional, ya lo hace Node.js)
        try:
            os.remove(archivo_temporal)
            print(f"Archivo temporal eliminado: {archivo_temporal}", file=sys.stderr)
        except:
            pass
            
    except Exception as e:
        print(f"Error procesando archivo: {str(e)}", file=sys.stderr)
        print(json.dumps({"error": f"Error procesando archivo: {str(e)}"}))

if __name__ == "__main__":
    main()