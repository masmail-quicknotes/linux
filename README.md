# linux

- [IPtables](#iptables)

- [Netplan](#netplan)

- [Bash](#bash)
  - [Ejemplo bucle For](#ejemplo-bucle-for)
  - [Ejemplo bucle While infinito](#ejemplo-bucle-while-infinito)  
  
- [Shell-script](#shell-script)
  - [Inicio Bash](#inicio-bash)
  - [Function](#Function)
  - [IF - ELIF - ELSE - FI ](#if-elif-else-fi)
  - [Petición parámetros](#peticion-parámetros)
  - [case](#case)  
  
- [Diff](#diff)

***

# IPtables

    sudo apt-get install iptables-persistent netfilter-persistent

    vi  /etc/iptables/rules.v4 
    # Generated by iptables-save v1.6.1 on Thu Mar  5 11:22:52 2020
    *filter
    :INPUT DROP [0:0]
    :FORWARD ACCEPT [0:0]
    :OUTPUT ACCEPT [0:0]
    :LOGGING - [0:0]
    -A INPUT -i lo -j ACCEPT
    -A INPUT -d 127.0.0.0/8 ! -i lo -j REJECT --reject-with icmp-port-unreachable
    -A INPUT -m state --state RELATED,ESTABLISHED -j ACCEPT
    -A INPUT -s 192.168.14.0/25 -p tcp -m tcp --dport 22 -m comment --comment "SSH" -j ACCEPT
    -A INPUT -p icmp -m comment --comment "PING" -j ACCEPT
    -A INPUT -j LOGGING
    -A LOGGING -m limit --limit 2 \/min -j LOG --log-prefix "IPTables:DROP: "
    -A LOGGING -j DROP
    COMMIT
    \# Completed on Thu Mar  5 11:22:52 2020
 \
    cat /etc/rsyslog.d/40-iptables.conf 
    :msg, regex, "iptables:" -/var/log/firewall.log
     & ~

    sudo /etc/init.d/rsyslog restart


# Netplan

Ejemplo fichero netplan:

    vi /etc/netplan/99-netcfg.yaml 
    network:
       version: 2
       renderer: networkd
       ethernets:
         ens192:
           dhcp4: no
           dhcp6: no
           addresses:
             - 192.168.1.100/24
           gateway4: 192.168.1.1
           nameservers:
             addresses:
               - 9.9.9.9
               - 8.8.8.8 
          
    netplan apply

***

# Bash

## Ejemplo Bucle For
    for i in $(ls -a); do echo "fichero ${i}"; done

## Ejemplo Bucle While infinito
    while [ true ]; do echo "hello world\n"; sleep 3; done

***

# Shell-script

# Inicio bash

    #!/bin/bash
    
    ECHO=$(which echo)
    CAT=$(which cat)
    NMAP=$(which nmap)
    RM=$(which rm)
    DIFF=$(which diff)
     ...

# Function 

    function Usage () {
            ${ECHO} -e "SYNTAX ERROR: ${0} [opcion1|opcion2] <nombre>\n"
            exit 1
    }
  
## IF - ELIF - ELSE - FI

Verificamos los parametros si son nulos, y si primer parametro contiene valor correcto.

    if [[ -z ${1} ]] || [[ -z ${2} ]] ; then
      Usage
    elif [[ "${1}" != "opcion1" ]] && [[ "${1}" != "opcion2" ]] ; then
      Usage
    else
    	accion="${1}"
    	nombre="${2}"
    fi

Si fichero existe entonces lo borramos:

    if [[ -f "${nombreFichero}" ]] ; then
      ${RM} ${nombreFichero}
    fi


## Petición parámetros

    ${ECHO} "Introduce un nombre:"
    read -s nombre

## Case 

    case $opcion in
      0)
        ${ECHO} -e "[CORRECTO];"
        ;;
      *)
        ${ECHO} -e "[INCORRECTO];"
        ;;
    esac

***
# Diff

## Ejemplo visualización en columnas

    diff -y fichero1.txt fichero2.txt

## Ejemplo comparar sin diferenciar espacios en blanco ni tabuladores

    diff -wEZB  fichero1.txt fichero2.txt

## Ejemplo modo silencioso

Importa el resultado del commando diff result=0 EXIT OK, result=1 FAIL.

    result=$(diff -q --ignore-matching-lines="ntp clock-period" fichero1.txt fichero2.txt)

## Ejemplo ignorando lineas

Las líneas con contenido "ntp clock-period" son ignoradas.

    diff --ignore-matching-lines="ntp clock-period" fichero1.txt fichero2.txt

## Comandos utilies del diff 

    diff 
          --suppress-blank-empty     suppress space or tab before empty output lines
          -y, --side-by-side         output in two columns
          -w, --ignore-all-space     ignore all white space
          -B, --ignore-blank-lines   ignore changes where lines are all blank
          -i, --ignore-case          ignore case differences in file contents
          -E, --ignore-tab-expansion ignore changes due to tab expansion
          -q, --brief                report only when files differ
          --suppress-common-lines    do not output common lines

***

## URLs Referencia:

- <https://www.computerhope.com/unix/udiff.htm>
