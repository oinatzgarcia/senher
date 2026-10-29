# SENHER

**SENHER** es una herramienta de enumeración y validación de subdominios para Kali Linux. Automatiza la recolección pasiva, activa, la generación de permutaciones, la validación DNS y la generación de informes en HTML y Markdown.

## Características

- Enumeración pasiva con **Subfinder**, **Amass**, **Shodan API** y **GAU**
- Generación de permutaciones con **AlterX** y **Gotator**
- Validación de resolución DNS con **dnsx**
- Consulta WHOIS del dominio objetivo
- Deduplicación automática y filtrado por scope
- Resultados organizados por fecha en `output/`
- Informe visual en HTML con subdominios agrupados por IP
- Informe técnico en Markdown con los subdominios válidos

## Flujo de trabajo

```text
Subfinder + Amass + Shodan + GAU
              |
              v
     Deduplicación / scope
              |
              v
   AlterX + Gotator (permutaciones)
              |
              v
       dnsx (validación DNS)
              |
              v
 report.html + REPORT.md + 03_resolved.txt
```

## Requisitos

- Kali Linux o cualquier distribución basada en Debian
- Python 3.8 o superior
- Go instalado
- Una API key de [Shodan](https://account.shodan.io/)

## Instalación

### Dependencias del sistema

```bash
sudo apt update
sudo apt install -y whois golang-go
pip3 install -r requirements.txt
```

### Herramientas externas

```bash
go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
go install -v github.com/owasp-amass/amass/v5/cmd/amass@main
go install -v github.com/projectdiscovery/dnsx/cmd/dnsx@latest
go install -v github.com/projectdiscovery/alterx/cmd/alterx@latest
go install -v github.com/Josue87/gotator@latest
go install -v github.com/lc/gau/v2/cmd/gau@latest
```

Añade los binarios de Go al PATH:

```bash
echo 'export PATH=$PATH:$HOME/go/bin' >> ~/.zshrc
source ~/.zshrc
```

Si usas Bash:

```bash
echo 'export PATH=$PATH:$HOME/go/bin' >> ~/.bashrc
source ~/.bashrc
```

### Clonar el repositorio

```bash
git clone https://github.com/oinatzgarcia/senher.git
cd senher
```

## Configuración de Shodan

Exporta tu API key como variable de entorno:

```bash
export SHODAN_API_KEY="TU_API_KEY"
```

Para hacerlo permanente:

```bash
echo 'export SHODAN_API_KEY="TU_API_KEY"' >> ~/.zshrc
source ~/.zshrc
```

También puedes pasarla directamente al ejecutar la herramienta:

```bash
python3 subenum.py ejemplo.com --shodan-key "TU_API_KEY"
```

> No incluyas la API key en el código ni la subas al repositorio.

## Uso

### Enumeración pasiva completa

```bash
python3 subenum.py ejemplo.com
```

### Con wordlist de permutaciones

```bash
python3 subenum.py ejemplo.com \
  --perm-list /usr/share/seclists/Discovery/DNS/deepmagic.com-prefixes-top500.txt
```

### Enumeración activa

```bash
python3 subenum.py ejemplo.com --active \
  --wordlist /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt
```

### Omitir fases

```bash
python3 subenum.py ejemplo.com --skip-amass
python3 subenum.py ejemplo.com --skip-gau
python3 subenum.py ejemplo.com --skip-shodan
python3 subenum.py ejemplo.com --skip-permutations
```

## Parámetros

| Parámetro | Descripción |
|---|---|
| `domain` | Dominio objetivo, por ejemplo `ejemplo.com` |
| `-k, --shodan-key` | API key de Shodan |
| `-o, --output-dir` | Directorio personalizado de salida |
| `--resolvers` | Archivo con resolvers DNS |
| `--wordlist` | Wordlist para enumeración activa con Amass |
| `--perm-list` | Wordlist para Gotator |
| `--active` | Habilita enumeración activa |
| `--threads` | Número de hilos para dnsx |
| `--skip-amass` | Omite Amass |
| `--skip-gau` | Omite GAU |
| `--skip-shodan` | Omite la API de Shodan |
| `--skip-permutations` | Omite AlterX y Gotator |

## Resolvers

Crea o utiliza el archivo `resolvers.txt` incluido, con servidores DNS uno por línea:

```text
1.1.1.1
1.0.0.1
8.8.8.8
9.9.9.9
```

## Informe HTML

Al finalizar, SENHER genera automáticamente `report.html` dentro del directorio de resultados.

```bash
xdg-open output/ejemplo.com_*/report.html
```

El informe HTML incluye:

- Resumen con el número de subdominios pasivos, permutaciones, hosts DNS válidos e IPs únicas
- Tabla de **subdominios agrupados por IP**
- Tabla de **detalle por subdominio**
- Direcciones **IPv4**, **IPv6** y registros **CNAME**
- Origen de cada host: pasivo o permutación
- Enlaces directos a cada subdominio
- Ordenación por IP y, después, alfabéticamente por subdominio

### Ejemplo de agrupación

| IP | Subdominios |
|---|---|
| `203.0.113.10` | `www.ejemplo.com`, `api.ejemplo.com` |
| `203.0.113.25` | `mail.ejemplo.com` |
| `2001:db8::10` | `cdn.ejemplo.com` |

Esto permite identificar rápidamente infraestructura compartida, servidores con múltiples servicios y posibles relaciones entre subdominios.

## Resultados

SENHER crea un directorio con fecha y hora:

```text
output/ejemplo.com_20261029_120000/
├── subfinder.txt
├── amass.txt
├── shodan.txt
├── gau.txt
├── 01_passive_all.txt
├── alterx.txt
├── gotator.txt
├── 02_permutations.txt
├── 03_resolved.txt
├── whois.txt
├── REPORT.md
└── report.html
```

| Archivo | Contenido |
|---|---|
| `01_passive_all.txt` | Subdominios pasivos únicos |
| `02_permutations.txt` | Permutaciones generadas |
| `03_resolved.txt` | Subdominios con resolución DNS válida |
| `REPORT.md` | Informe técnico en Markdown con resolución por IP |
| `report.html` | Informe visual en HTML con IPs y subdominios |

## Herramientas utilizadas

- [Subfinder](https://github.com/projectdiscovery/subfinder) — enumeración pasiva de subdominios
- [Amass](https://github.com/owasp-amass/amass) — mapeo de superficie de ataque
- [Shodan](https://www.shodan.io/) — información DNS y subdominios conocidos
- [GAU](https://github.com/lc/gau) — URLs históricas de OTX, Wayback, Common Crawl y URLScan
- [AlterX](https://github.com/projectdiscovery/alterx) — generación de permutaciones de subdominios
- [Gotator](https://github.com/Josue87/gotator) — generación de wordlists DNS
- [dnsx](https://github.com/projectdiscovery/dnsx) — resolución y validación DNS
- [whois](https://packages.debian.org/stable/whois) — información de registro del dominio

## Licencia

Este proyecto se distribuye bajo licencia MIT.

## Autor

**oinatzgarcia**  
https://github.com/oinatzgarcia
