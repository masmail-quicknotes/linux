# linux

- [find](#find)

- [grep](#grep)

- [sort & uniq](#sort-uniq)

- [sed](#sed)

- [awk](#awk)

- [diff](#diff)

- [Bash](#bash)
  - [Ejemplo bucle For](#ejemplo-bucle-for)
  - [Ejemplo bucle While infinito](#ejemplo-bucle-while-infinito)  
  
- [Shell-script](#shell-script)
  - [Inicio Bash](#inicio-bash)
  - [Function](#function)
  - [IF - ELIF - ELSE - FI ](#if---elif---else---fi)
  - [Petición parámetros](#petición-parámetros)
  - [case](#case)  
  
- [IPtables](#iptables)

- [Netplan](#netplan)

***

# Find

## Find searches a directory for files 

    find /tmp -type d -print

## Find a filename

    find / -name '*.txt'
    
## Find type

    find -type [TYPE]
      f: regular file
      d: directory
      l: symlink
      p: named pipe
      s: socket
      
    find /tmp -type d,l

## Find path and ipath

Search the full path, and ipath (case insensitive)

    find / -path '*tmp*/*'
  
## Find maxdepth

Only descend NUM levels when searching a directory.

    find / -path '*tmp*/*' -maxdepth 2
    
## Find -mtime

Files that were modified at most NUM days in the past.

    find / -name '*.py' -mtime 2

## Find -print

Action: print filename of files found.

    find . -name '*.py' -mtime 0 -print
    ./test.py
    ./test3.py
    ./test2.py

    find . -name '*.py' -mtime 0 -print0 
    ./test.py./test3.py./test2.py

    find . -name '*.py' -mtime 0 -print0 | xargs -0
    ./test.py ./test3.py ./test2.py

## Find -exec

Action: run COMMAND on every file found.

    find . -name '*.py' -mtime 0 -exec ls -l '{}' \;
    find . -name '*.py' -mtime 0 -exec cat '{}' \;

## Find -delete

Action: delete all files found

    find . -name '*.py' -mtime 0 -delete

## Locate and updatedb

The `locate` command searches a adatabase of eery file on your system. Faster than find, but cant get out of date.

Updates the database:

    $ sudo updatedb

***

# grep

`grep` lets you search fiels for text

## grep -i

Case insensitive.

    $ grep -i Apple foo.txt 
    apple

## grep -e or egrep

Search regular expressions.

    $ grep -e '^....$' foo.txt 
    kiwi

## grep -v

Invert match, find all lines that don't match.

    $ grep -ve '^....$' foo.txt 
    apple
    banana
    orange

## grep -l

Only show the filenames of the files that matched.

    $ grep -le '^....$' *.txt 
    foo.txt

## grep -o

Only print the matching part of the line (not the whole line).

    $ grep 'kiwi' foo.txt 
    kiwi
    kiwi with orange

    $ grep -o 'kiwi' foo.txt 
    kiwi
    kiwi

## grep -A -B -C

Show `context` for your search.

Will show 1 line of context `a`fter a match, `b`efore a match, `c`ontext.

    $ grep -A 1 'banana' foo.txt 
    banana
    orange

    $ grep -B 1 'banana' foo.txt 
    apple
    banana

    $ grep -C 1 'banana' foo.txt 
    apple
    banana
    orange

## grep -F

Don't treat the match string as a regex.

## grep -r

Recursive. Search all the files in a directory.

## grep -a 

Search binaries: threat binary data like it's text instead of ignoring it.

***

# sort & uniq

`sort` sorts its input. The default sort is alphabetical.

    $ sort foo.txt 
    apple,10
    banana,5
    kiwi with orange,10000
    kiwi,500
    orange,1000

## sort -n

Numeric sort on second column.

    $ sort -n -t ',' -k 2 foo.txt 
    banana,5
    apple,10
    kiwi,500
    orange,1000
    kiwi with orange,10000

## sort -h

Human sort.

    $ sort -h -t ',' -k 2 foo.txt 
    banana,5
    apple,10
    kiwi,500
    orange,1K
    kiwi with orange,10K

Useful example:

    $ du -sh * | sort -h

## sort + uniq

Pipe something to `sort | uniq` and you'll get a deduplicated list of lines. `sort -u` does the same thing.

    $ cat foo2.txt 
    apple
    banana
    orange
    apple
    kiwi
    orange
    orange
    kiwi
    apple
    orange

    $ cat foo2.txt | sort | uniq
    apple
    banana
    kiwi
    orange

    $ sort -u foo2.txt 
    apple
    banana
    kiwi
    orange

`uniq -c` counts each line it saw.

    $ cat foo2.txt | sort | uniq -c
          3 apple
          1 banana
          2 kiwi
          4 orange

Get the top 10 most common lines in a file.

    $ sort foo2.txt | uniq -c | sort -rn | tail -n 10
          4 orange
          3 apple
          2 kiwi
          1 banana

***

# sed

`sed` is most often used for replacing text in a file.

## sed replace

Replaces orange by lemon.  
  
    $ sed s/orange/lemon/g foo2.txt 
    apple
    banana
    lemon
    apple
    kiwi
    lemon
    lemon
    kiwi
    apple
    lemon

## sed delete

Delete 5th line.

    $sed 5d foo2.txt 
    apple
    banana
    orange
    apple
    orange
    orange
    kiwi
    apple
    orange

Delete lines matching `kiwi`.

    $ sed /kiwi/d foo2.txt 
    apple
    banana
    orange
    apple
    orange
    orange
    apple
    orange

## sed print

Print line 5-8

    $ cat -n foo2.txt 
         1	apple
         2	banana
         3	orange
         4	apple
         5	kiwi
         6	orange
         7	orange
         8	kiwi
         9	apple
        10	orange
    
    $ sed -n 5,8p foo2.txt 
    kiwi
    orange
    orange
    kiwi

## sed change in place

Change a file in place with `-i`.

    $ sed -i s/orange/lemon/g foo2.txt 

    $ cat foo2.txt 
    apple
    banana
    lemon
    apple
    kiwi
    lemon
    lemon
    kiwi
    apple
    lemon

    $ sed -i s/lemon/orange/g foo2.txt 

    $ cat foo2.txt 
    apple
    banana
    orange
    apple
    kiwi
    orange
    orange
    kiwi
    apple
    orange

## sed changed lines

Only print changed lines.

    $ sed -n s/orange/lemon/p foo2.txt
    lemon
    lemon
    lemon
    lemon

## sed regex delimeter

Use this if your regex has a `/` in it.

    $ sed s#orange#lemon#g foo2.txt
    apple
    banana
    lemon
    apple
    kiwi
    lemon
    lemon
    kiwi
    apple
    lemon

## sed double space a file

Double space a file.

    $ sed G foo2.txt 
    apple

    banana

    orange

    apple

    kiwi

    orange

    orange

    kiwi

    apple

    orange

## sed append after

Added `grape` `a`fter `banana`.

    $ sed '/banana/a grape' foo2.txt 
    apple
    banana
    grape
    orange
    apple
    kiwi
    orange
    orange
    kiwi
    apple
    orange

## sed insert on line

Inserted `grape` before `banana`.

    $ sed '/banana/i grape' foo2.txt 
    apple
    grape
    banana
    orange
    apple
    kiwi
    orange
    orange
    kiwi
    apple
    orange

Insert on line number 4 `grape`

    $ sed '4i grape' foo2.txt 
    apple
    banana
    orange
    grape
    apple
    kiwi
    orange
    orange
    kiwi
    apple
    orange

***

# awk

`awk` is a tiny programming language for manipulating columns of data.

## awk structure

Basic awk program structure. Do {action} on line matching CONDITION.

    BEGIN { ... }
    CONDITION {action}
    CONDITION {action}
    END { ... }

## awk print

    $ awk -F, '{ print $0 }' foo3.txt 
    apple,10
    banana,5
    kiwi,500
    orange,1000
    apple,18
    kiwi,10000

## awk extract a column

Extract a column of text with awk, with column separator comma.

    $ awk -F, '{ print $2 }' foo3.txt 
    10
    5
    500
    1000
    18
    10000

## awk sum

sum the numbers in the 2nd column. 

    $ awk -F, '{ s+=$2 } END { print s }' foo3.txt 
    11533

## awk condition

Only sum numbers > 100.

    $ awk -F, '$2 > 100 { s+=$2 } END { print s }' foo3.txt 
    11500

Print lines where first column is longer than 4 characters. Implicit {print} as the action.

    $ awk -F, 'length($1)>4' foo3.txt 
    apple,10
    banana,5
    orange,1000   
490
​
491

    apple,18

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

# Bash

## Ejemplo Bucle For
    for i in $(ls -a); do echo "fichero ${i}"; done

## Ejemplo Bucle While infinito
    while [ true ]; do echo "hello world\n"; sleep 3; done

***

# Shell-script

## Inicio bash

    #!/bin/bash
    
    ECHO=$(which echo)
    CAT=$(which cat)
    NMAP=$(which nmap)
    RM=$(which rm)
    DIFF=$(which diff)
     ...

## Function

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
     
    vi \/etc\/rsyslog.d\/40-iptables.conf    
    :msg, regex
    , "iptables:" -\/var\/log\/firewall.log    
    \& \~
    
    sudo /etc/init.d/rsyslog restart

***

# Netplan
    \& 
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

## URLs Referencia:

- <https://www.computerhope.com/unix/udiff.htm>
- <https://twitter.com/b0rk>
