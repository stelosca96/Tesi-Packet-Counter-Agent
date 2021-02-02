# Packet-Counter-Agent

## Configurazione

Modificare nel Makefile la variabile `LINUX_SRC` -> Percorso della cartella con i sorgenti

## Installazione

1. `make`
2. `scp counter_agent.ko root@192.168.100.1:{cartella_modulo}`
3. Accedere nella cartella `{cartella_modulo}` sul router
4. `insmod counter_agent.ko`
5. Per rimuovere il modulo `rmmod counter_agent.ko`
6. Per impostare l'auto avvio
  1. `cp counter_agent.ko /lib/modules/4.14.98-tgr/kernel/drivers/`
  2. `echo 'counter_agent' | tee -a /etc/modules`
  3. `depmod`

## Utilizzo

### Per aggiungere indirizzi e porte sui cui contare pacchetti

```bash
cat test.conf >> /proc/udp_tcp_counter
```

Il file di configurazione deve avere questa struttura:

#### test.conf

```txt
192.168.1.1 80
192.168.1.1 8080
192.168.1.55 8096
```

### Per visualizzare i contatori

```bash
cat /proc/udp_tcp_counter 
```

I contatori saranno in questo formato:

```txt
tcp_packets 104383
tcp_syn_packets 400
udp_packets 3372
udp_throughput 1849125,
udp_packets_53 204
udp_throughput_53 32421
tcp_packets_192.168.1.1:80 125
tcp_syn_packets_192.168.1.1:80 6
tcp_packets_192.168.1.1:8080 0
tcp_syn_packets_192.168.1.1:8080 0
tcp_packets_192.168.1.55:8096 4244
tcp_syn_packets_192.168.1.55:8096 7
```
