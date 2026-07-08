```text
[Tu Computadora: DBeaver] 
       │
       ▼ (Túnel SSH seguro en puerto 22)
[Servidor DigitalOcean: Droplet] 
       │
       ▼ (Escucha interna en puerto 5434 por Contenedor 'db-bridge')
[Red Interna: dokploy-network] 
       │
       ▼ (Redirección interna automática)
[Contenedor Base de Datos: ejemplo-db-p1kjkt (<IP_INTERNA_REAL>:5432)]

```

***

# Documentación Técnica: Conexión SSH a Base de Datos en Dokploy (Docker Swarm) desde DBeaver

## Contexto del Problema
Al desplegar una base de datos PostgreSQL usando **Dokploy**, esta se configura automáticamente dentro de una red aislada de Docker Swarm de tipo *overlay* (`dokploy-network`). Por motivos de seguridad, el puerto de la base de datos (`5432`) no se expone a Internet.

Intentar conectar DBeaver usando un túnel SSH estándar fallaba con un error de `EOFException` o `Read timed out`. Esto ocurre porque el usuario `root` del servidor principal (Droplet) no puede enrutar el tráfico directamente hacia la IP interna de la red aislada de Docker Swarm (`10.0.x.x`) de forma nativa desde un túnel externo.

---

## La Solución General
Para solucionar este aislamiento sin abrir el Firewall ni exponer la base de datos a Internet, se creó un **puente de red interno (`socat`)** dentro del propio servidor. 

Este puente escucha un puerto libre en el Droplet (puerto **`5434`**) y redirige de forma transparente todo el tráfico a través de la red interna de Dokploy hacia el contenedor de PostgreSQL en el puerto `5432`.

<br>
<br>
<br>

## 🛠️ Guía de Reconstrucción Paso a Paso (Para un nuevo Droplet)

Si creas un nuevo Droplet y redespliegas tu aplicación, sigue estos pasos para dejar la conexión lista:

### Paso 1: Identificar los datos en Dokploy
Una vez desplegada tu base de datos en el nuevo Dokploy, ve a la configuración de la misma y anota:

* El **Internal Host** (ej. `ejemplo-db-p1kjkt`).
* Las credenciales de acceso (`Database Name`, `User`, `Password`).

### Paso 2: Obtener la IP interna del contenedor
Entra a la **Web Console** (Consola negra) de tu nuevo Droplet de DigitalOcean y ejecuta este comando para listar los contenedores y encontrar la IP interna de tu base de datos:

```
docker ps -q | xargs docker inspect --format '{{.Name}} - {{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}'
```

Identifica la línea de tu base de datos y copia la IP interna.

### Paso 3: Identificar el nombre de la red de Dokploy

Ejecuta el siguiente comando para confirmar cómo se llama la red overlay de Dokploy:

```
docker network ls
```

Por defecto en Dokploy, la red se llama ```dokploy-network.```

### Paso 4: Crear el puente de red permanente (db-bridge)

Ejecuta el siguiente comando en la consola del Droplet. Nota: Recuerda cambiar `<IP_INTERNA_REAL>` por la IP interna real que obtuviste en el Paso 2

```
docker run -d \
  --name db-bridge \
  --network dokploy-network \
  --restart always \
  -p 5434:5432 \
  alpine/socat tcp-listen:5432,fork,reuseaddr tcp-connect:<IP_INTERNA_REAL>:5432
```
### Notas clave de este comando:

* `-d`: Corre en segundo plano (puedes cerrar la consola y seguirá funcionando).
* `--restart always`: Si el servidor se reinicia o se apaga, el puente se levantará automáticamente de nuevo.
* `-p 5434:5432`: Abre el puerto `5434` en el Droplet principal y lo conecta al `5432` del puente.

<br>
<br>
<br>

## 💻 Configuración Final en DBeaver

Cualquier miembro del grupo que use DBeaver debe configurar la conexión utilizando dos pestañas:

### 1. Pestaña SSH
Permite tunelizar la conexión de forma segura encriptando el tráfico hacia el Droplet:

* **Host/IP:** La IP pública de tu Droplet (ej. `192.0.2.1`).
* **Port:** `22`
* **User Name:** `root`
* **Authentication Method:** `Password`
* **Password:** La contraseña de acceso principal (root) del Droplet.

### 2. Pestaña General (Main)
Engaña a DBeaver para que busque el puente que construimos en el puerto `5434` una vez que el SSH haya entrado al Droplet:

* **Connect by:** `Host`
* **Host:** `localhost` o `127.0.0.1` *(porque una vez cruzado el SSH, DBeaver ya está "dentro" del servidor)*.
* **Port:** **`5434`** *(El puerto mapeado del puente socat)*.
* **Database:** El nombre de tu base de datos (ej. `ejemplodb`).
* **Username:** El usuario de la base de datos (ej. `ejemplo`).
* **Password:** La contraseña de la base de datos (ej. `ejemplo123`).