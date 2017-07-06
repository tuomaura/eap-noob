#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <time.h>
#include <unistd.h>
#include <nfc/nfc.h>

//#include "nfc-utils.h"


static nfc_device *nfc;
static nfc_context *context;

static uint8_t CMD_SELECT_HCE[] = {0x00, 0xa4, 0x04, 0x00, 0x05, 0xF2, 0x22, 0x22, 0x22, 0x22};
//static uint8_t SAMPLE[] = {0x00,0x01, 0x02, 0x03,0x04};
static uint8_t SAMPLE[] = "www.gmail.com";

static void stop_communication(int sig)
{
  (void) sig;
  if(nfc)
    nfc_abort_command(nfc);

  nfc_close(nfc);
  nfc_exit(context);
  exit(EXIT_FAILURE);
}

void
print_hex(const uint8_t *pbtData, const size_t szBytes)
{
  size_t  szPos;

  for (szPos = 0; szPos < szBytes; szPos++) {
    printf("%02x  ", pbtData[szPos]);
  }
  printf("\n");
}

void
print_nfc_target(const nfc_target *pnt, bool verbose)
{
  char *s;
  str_nfc_target(&s, pnt, verbose);
  printf("%s", s);
  nfc_free(s);
}


int read_card()
{

	int control = 1;
	uint8_t *command = NULL;
        uint8_t response[250];
        uint8_t *response_wo_status;
        int szCommand, szResponse;
	struct timeval tv;
	nfc_modulation nmIso14443A = {
            .nmt = NMT_ISO14443A,
            .nbr = NBR_106,
        };

        nfc_target ntIso14443A;

	//printf("waiting for a target ...\n");

	while(control){

		//gettimeofday(&tv, NULL);
		//printf("time  stamp 1 = %lu:%lu\n", tv.tv_sec,tv.tv_usec);
		if(nfc_initiator_select_passive_target(nfc, nmIso14443A,
                                           NULL, 0, &ntIso14443A)){
        		//print_nfc_target(&ntIso14443A, false);
			//gettimeofday(&tv, NULL);
			//printf("time stamp 2 = %lu:%lu\n", tv.tv_sec,tv.tv_usec);
#if 1
			//command = CMD_SELECT_AID;
			command = CMD_SELECT_HCE;
			szCommand = sizeof(CMD_SELECT_HCE);
			//printf("Command: %s\n", command);
			//print_hex(command, szCommand);
			//gettimeofday(&tv, NULL);
			//printf("time stamp 3 = %lu:%lu\n", tv.tv_sec,tv.tv_usec);
			szResponse = nfc_initiator_transceive_bytes(nfc, command, szCommand, response, sizeof(response), 0);
			response_wo_status = malloc(sizeof(uint8_t)* szResponse-1);
			strncpy(response_wo_status, response, szResponse-2);
			response_wo_status[szResponse-2] = '\0';
			printf("%s\n", response_wo_status);
			//gettimeofday(&tv, NULL);
			//printf("time stamp 4 = %lu:%lu\n", tv.tv_sec,tv.tv_usec);
			//printf("Response length: %d \n", szResponse);
			//print_hex(response, szResponse);
#endif
#if 0			

			command = SAMPLE;
			szCommand = sizeof(SAMPLE);
			printf("Command: %s\n", command);
			print_hex(command, szCommand);
			szResponse = nfc_initiator_transceive_bytes(nfc, command, szCommand, response, sizeof(response), 0);

			printf("Response : %s \n", response);
			printf("Response length: %d \n", szResponse);
			print_hex(response, szResponse);


#endif
			//sending something



			control = 0;
		}
	}
}
int main(int argc, char *argv[])
{



        nfc_init(&context);
        if(context == NULL) {
                //ERR("Unable to init libnfc (malloc) ");
        	exit(EXIT_FAILURE);
        }

        // Try to open the NFC device
        nfc = nfc_open(context, NULL);
        if(nfc == NULL) {
        	//ERR("Unable to open NFC device. \n");
        	nfc_exit(context);
        	exit(EXIT_FAILURE);
        }

        if(nfc_initiator_init(nfc) < 0) {
            nfc_perror(nfc, "nfc_initiator_init");
            nfc_close(nfc);
            nfc_exit(context);
            exit(EXIT_FAILURE);
        }

        // Device may go responseless while waiting a tag for a long time
        // Therefore, let the device only return immediately after a try
        if(nfc_device_set_property_bool(nfc, NP_INFINITE_SELECT, false) < 0) {
            nfc_perror(nfc, "nfc_device_set_property_bool");
            nfc_close(nfc);
            nfc_exit(context);
            exit(EXIT_FAILURE);
        }
        //printf("NFC device: %s opened\n", nfc_device_get_name(nfc));

        signal(SIGINT, stop_communication); //stop on interrupt

        // the main loop
        read_card();

        //printf("Terminating DESFire Reader application.\n");
        nfc_close(nfc);
        nfc_exit(context);
        return 0;
}
