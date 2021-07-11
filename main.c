
#include <pcap.h>
#include <stdio.h>
#include <time.h>

/* Prototipo del manejador de paquetes */
void packet_handler(u_char *param, const struct pcap_pkthdr *header, const u_char *pkt_data);


int main()
{
	pcap_if_t *alldevs;
	pcap_if_t *d;
	int inum;
	int i=0;
	pcap_t *adhandle;
	char errbuf[PCAP_ERRBUF_SIZE];


	//Lista de interfaces de la máquina local
	if(pcap_findalldevs(&alldevs, errbuf) == -1)
	{
		fprintf(stderr,"Error in pcap_findalldevs: %s\n", errbuf);
		return -1;
	}

	//Muestra la lista
	for(d=alldevs; d; d=d->next)
	{
		printf("%d. %s", ++i, d->name);
		if (d->description)
			printf(" (%s)\n", d->description);
		else
			printf(" (No description available)\n");
	}

	if(i==0)
	{
		printf("\nNo interfaces found! Make sure Npcap is installed.\n");
		return -1;
	}

	//Se pide una interfaz al usuario
	printf("Enter the interface number (1-%d):",i);
	scanf("%d", &inum);

	if(inum < 1 || inum > i)
	{
		printf("\nInterface number out of range.\n");
		//Liberamos la lista de interfaces
		pcap_freealldevs(alldevs);
		return -1;
	}

	//Nos movemos al adaptador seleccionado
	for(d=alldevs, i=0; i< inum-1 ;d=d->next, i++);

	//Abrimos la interfaz y el adaptador
	if ((adhandle= pcap_open_live(d->name,	// nombre de la interfaz
							 65536,			// porción del paquete a capturar
											// 65536 garantiza que todos los paquetes llegarán a cualquier MAC
							 1,				// modo promiscuo
							 1000,			// tiempo de espera de lectura
							 errbuf			// error buffer
							 )) == NULL)
	{
		fprintf(stderr,"\nUnable to open the adapter. %s is not supported by Npcap\n", d->name);
		//Liberamos la lista de interfaces
		pcap_freealldevs(alldevs);
		return -1;
	}

	printf("\nlistening on %s...\n", d->description);

	//Liberamos la lista de interfaces ya que no vamos a utilizarla más
	pcap_freealldevs(alldevs);

	//Comenzamos la captura
	pcap_loop(adhandle, 0, packet_handler, NULL);

	pcap_close(adhandle);
	return 0;
}


//Función llamada por la librería libcap para cada paquete recibido
void packet_handler(u_char *param, const struct pcap_pkthdr *header, const u_char *pkt_data)
{
	struct tm *ltime;
	char timestr[16];
	time_t local_tv_sec;
	u_char *message;

	/* convert the timestamp to readable format */
	//Convertimos el timestamp a un formate legible
	local_tv_sec = header->ts.tv_sec;
	ltime=localtime(&local_tv_sec);
	strftime( timestr, sizeof timestr, "%H:%M:%S", ltime);

	//Almacenamos en message el paquete recibido
	message = pkt_data;

	//Filtramos los paquetes que coincidan con esta MAC y Ethertype
	if( message[0] == 0xFF &&
        message[1] == 0xFF &&
        message[2] == 0xFF &&
        message[3] == 0xFF &&
        message[4] == 0xFF &&
        message[5] == 0xFF &&
        message[12] == 0x21 &&
        message[13] == 0x21) {
            //Imprimimos el mensaje por pantalla
            for(int i = 14; i < header->len; i++) {
                printf("%c", message[i]);
            }
        }
}
