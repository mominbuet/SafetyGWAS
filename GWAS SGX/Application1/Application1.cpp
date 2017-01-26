// Application1.cpp : Defines the entry point for the console application.
//
/*
#include "stdafx.h"


int _tmain(int argc, _TCHAR* argv[])
{
	return 0;
}
*/
#include "stdafx.h"
#include <cstdio>
#include <stdio.h>
#include <vector>
#include <tchar.h>
#include<cstdio>
#include<iostream>
#include <fstream>
//#include <cstring>
#include <string>
#include "sgx_urts.h"
#include "Enclave1_u.h"
#define ENCLAVE_FILE _T("Enclave1.signed.dll")
#define ROWS 50
#define ATTRS 400
#define LIMIT 10


using namespace std;

void ocall_print_string(const char *str)
{
	/* Proxy/Bridge will check the length and null-terminate 
	* the input string to prevent buffer overflow. 
	*/
	printf("%s", str);
}



string number_to_string(int x){
    if(!x) return "0";
        string s,s2;
        while(x){
            s.push_back(x%10 + '0');
            x/=10;
        }
    reverse(s.begin(),s.end());
    return s;
}




int main(int argc, char* argv[])
{
	sgx_enclave_id_t eid;
	sgx_status_t ret = SGX_SUCCESS;
	sgx_launch_token_t token = {0};
	int updated = 0;
	char** buffer = new char*[ROWS];
	//values for LD calculation containing genotype counta
	char** ldValues = new char*[4];
	//values for HWE calculation containing genotype counts
	char** hweValues = new char*[4];
	//values for CATT calculation containing case control data
	char** cattValues = new char*[6];
	//values for FET calculation containing case control data
	//char** fetValues = new char*[6];
	// Create the Enclave with above launch token.
	ret = sgx_create_enclave(ENCLAVE_FILE, SGX_DEBUG_FLAG, &token, &updated, &eid, NULL);

	if (ret != SGX_SUCCESS)
	{
		printf("App: error %#x, failed to create enclave.\n", ret);
		return -1;
	}

	//processing command line argument strcmp(argv[1], std::string("0").c_str()) == 0

	if(argc < 2) return 0;

	if(atoi(argv[1]) == 0)
	{
		//LD;
		//char *N_AB, *N_Ab, *N_aB, *N_ab;

		ldValues[0] = (char*)malloc(strlen(argv[2]) + 1);
		strcpy(ldValues[0], argv[2]);

		ldValues[1] = (char*)malloc(strlen(argv[3]) + 1);
		strcpy(ldValues[1], argv[3]);

		ldValues[2] = (char*)malloc(strlen(argv[4]) + 1);
		strcpy(ldValues[2], argv[4]);

		ldValues[3] = (char*)malloc(strlen(argv[5]) + 1);
		strcpy(ldValues[3], argv[5]);

		char* result = new char[2];
		ld(eid, ldValues, result, strlen(argv[2])+strlen(argv[3])+strlen(argv[4])+strlen(argv[5])+4, 2);
	    cout<<result<<endl;
	}
	else if(atoi(argv[1]) == 1)
	{
		//HWE
		//char *N_AA, *N_Aa, *N_aa;

		hweValues[0] = (char*)malloc(strlen(argv[2] + 1));
		strcpy(hweValues[0], argv[2]);

		hweValues[1] = (char*)malloc(strlen(argv[3] + 1));
		strcpy(hweValues[1], argv[3]);

		hweValues[2] = (char*)malloc(strlen(argv[4] + 1));
		strcpy(hweValues[2], argv[4]);

		char* hweResult = new char[2];
		hwe(eid, hweValues, hweResult, strlen(argv[2])+strlen(argv[3])+strlen(argv[4])+3, 2);
	    cout<<hweResult<<endl;

	}
	else if((atoi(argv[1]) == 2) || (atoi(argv[1]) == 3))
	{
		//CATT or FET
		//char *N_AA_case, *N_Aa_case, *N_aa_case, *N_AA_control, *N_Aa_control, *N_aa_control;

		cattValues[0] = (char*)malloc(strlen(argv[2] + 1));
		strcpy(cattValues[0], argv[2]);

		cattValues[1] = (char*)malloc(strlen(argv[3] + 1));
		strcpy(cattValues[1], argv[3]);

		cattValues[2] = (char*)malloc(strlen(argv[4] + 1));
		strcpy(cattValues[2], argv[4]);

		cattValues[3] = (char*)malloc(strlen(argv[5] + 1));
		strcpy(cattValues[3], argv[5]);

		cattValues[4] = (char*)malloc(strlen(argv[6] + 1));
		strcpy(cattValues[4], argv[6]);

		cattValues[5] = (char*)malloc(strlen(argv[7] + 1));
		strcpy(cattValues[5], argv[7]);

		if(atoi(argv[1]) == 2)
		{
			//CATT
			char* cattResult = new char[2];
		    catt(eid, cattValues, cattResult, strlen(argv[2])+strlen(argv[3])+strlen(argv[4])+strlen(argv[5])+strlen(argv[6])+strlen(argv[7])+6, 2);
	        cout<<cattResult<<endl;
		}
		else
		{
			//FET
			char* fetResult = new char[2];
			fet(eid, cattValues, fetResult,  strlen(argv[2])+strlen(argv[3])+strlen(argv[4])+strlen(argv[5])+strlen(argv[6])+strlen(argv[7])+6, 2);
	        cout<<fetResult<<endl;
		}
	}
	else
	{
		//Invalid argument
		cout<<"error invalid argument \n";
	}

/*	
	//intialize ld values 
	char *N_AB, *N_Ab, *N_aB, *N_ab;
	N_AB="1388340523208509944494243759745514029105059285057091708395083517134203030435174719134152881150452427881525975765932940173288209778710872487104141749558595707460984083772056065467779121907419296662935268554166562272604932237720508588592700121881153232485200672493393341340028567734931478418511610610340986454";
	N_Ab="38677845208276928842985355139346991339986264443093110807911506535174471004365984019230924248088256651521563475200625601932634869982185305645516135592759610082839486874816461656826979417629398444289518134342545635443324705037191952851674855112444902784874910351662612777145689777488209053790486356291887611812";
	N_aB="85264774145632908145411471037001080926985661424253509845784271319788172814696196697991951615033606090568046705756654858283798442717055779691733639522732530136911286252701213049688637631321036911678017642997882023610371413221474039614891472111039998447511192000642320361467185164803236778058000117930490930238";
	N_ab="2946828928734514736277572110886032887946976670522381034318623111909980977927970914040573391819038462749791564304297472239092063764582534464607673357695018293762259925946123447096918458615762092220283626049905442738692672832529780621596781349044424561284734514182628791476855125560352586842263204402650149776";

	ldValues[0] = new char[strlen(N_AB)];
	strcpy(ldValues[0], N_AB);

	ldValues[1] = new char[strlen(N_Ab)];
	strcpy(ldValues[1], N_Ab);

	ldValues[2] = new char[strlen(N_aB)];
	strcpy(ldValues[2], N_aB);

	ldValues[3] = new char[strlen(N_ab)];
	strcpy(ldValues[3], N_ab);

	//cout<<ldValues[0]<<endl;

	char* result = new char[350];
	ld(eid, ldValues, result, strlen(N_AB)+strlen(N_Ab)+strlen(N_aB)+strlen(N_ab)+4, 2);
	cout<<result<<endl;

	//intialize hwe values 
	char *N_AA, *N_Aa, *N_aa;
	N_AA="1388340523208509944494243759745514029105059285057091708395083517134203030435174719134152881150452427881525975765932940173288209778710872487104141749558595707460984083772056065467779121907419296662935268554166562272604932237720508588592700121881153232485200672493393341340028567734931478418511610610340986454";
	N_Aa="38677845208276928842985355139346991339986264443093110807911506535174471004365984019230924248088256651521563475200625601932634869982185305645516135592759610082839486874816461656826979417629398444289518134342545635443324705037191952851674855112444902784874910351662612777145689777488209053790486356291887611812";
	N_aa="85264774145632908145411471037001080926985661424253509845784271319788172814696196697991951615033606090568046705756654858283798442717055779691733639522732530136911286252701213049688637631321036911678017642997882023610371413221474039614891472111039998447511192000642320361467185164803236778058000117930490930238";

	hweValues[0] = new char[strlen(N_AA)];
	strcpy(hweValues[0], N_AA);

	hweValues[1] = new char[strlen(N_Aa)];
	strcpy(hweValues[1], N_Aa);

	hweValues[2] = new char[strlen(N_aa)];
	strcpy(hweValues[2], N_aa);

	char* hweResult = new char[350];
	hwe(eid, hweValues, hweResult, 1350, 350);
	cout<<hweResult<<endl;

	
	//initialize catt values
	char *N_AA_case, *N_Aa_case, *N_aa_case, *N_AA_control, *N_Aa_control, *N_aa_control;
	N_AA_case="1388340523208509944494243759745514029105059285057091708395083517134203030435174719134152881150452427881525975765932940173288209778710872487104141749558595707460984083772056065467779121907419296662935268554166562272604932237720508588592700121881153232485200672493393341340028567734931478418511610610340986454";
	N_Aa_case="38677845208276928842985355139346991339986264443093110807911506535174471004365984019230924248088256651521563475200625601932634869982185305645516135592759610082839486874816461656826979417629398444289518134342545635443324705037191952851674855112444902784874910351662612777145689777488209053790486356291887611812";
	N_aa_case="85264774145632908145411471037001080926985661424253509845784271319788172814696196697991951615033606090568046705756654858283798442717055779691733639522732530136911286252701213049688637631321036911678017642997882023610371413221474039614891472111039998447511192000642320361467185164803236778058000117930490930238";
	N_AA_control="38677845208276928842985355139346991339986264443093110807911506535174471004365984019230924248088256651521563475200625601932634869982185305645516135592759610082839486874816461656826979417629398444289518134342545635443324705037191952851674855112444902784874910351662612777145689777488209053790486356291887611812";
	N_Aa_control="85264774145632908145411471037001080926985661424253509845784271319788172814696196697991951615033606090568046705756654858283798442717055779691733639522732530136911286252701213049688637631321036911678017642997882023610371413221474039614891472111039998447511192000642320361467185164803236778058000117930490930238";
	N_aa_control="2946828928734514736277572110886032887946976670522381034318623111909980977927970914040573391819038462749791564304297472239092063764582534464607673357695018293762259925946123447096918458615762092220283626049905442738692672832529780621596781349044424561284734514182628791476855125560352586842263204402650149776";

	cattValues[0] = new char[strlen(N_AA_case)];
	strcpy(cattValues[0], N_AA_case);

	cattValues[1] = new char[strlen(N_Aa_case)];
	strcpy(cattValues[1], N_Aa_case);

	cattValues[2] = new char[strlen(N_aa_case)];
	strcpy(cattValues[2], N_aa_case);

	cattValues[3] = new char[strlen(N_AA_control)];
	strcpy(cattValues[3], N_AA_control);

	cattValues[4] = new char[strlen(N_Aa_control)];
	strcpy(cattValues[4], N_Aa_control);

	cattValues[5] = new char[strlen(N_aa_control)];
	strcpy(cattValues[5], N_aa_control);

	char* cattResult = new char[450];
	catt(eid, cattValues, cattResult, 2000, 350);
	cout<<cattResult<<endl;

	char* fetResult = new char[450];
	fet(eid, cattValues, fetResult, 2000, 350);
	cout<<fetResult<<endl;
*/	

	////vector<string> list;
	//ifstream infile; 
	//infile.open("C:\\Sadat\\MProjects\\projecta\\Application1\\encrypted_dataset.txt"); 


	///*std::ifstream infile("user_profile_data_2000.txt");*/
	//std::string line;
	//int i=0;
	//if (infile.is_open()) {
	//	while (std::getline(infile, line))
	//	{
	//		buffer[i] = new char[line.size() + 1];
	//		const char* tmp = line.c_str();
	//		
	//		strcpy(buffer[i],(char*) tmp);
	//		//cout<<buffer[i] <<endl;
	//		/*std::string  c (buffer[i]);
	//		printf("%s\n",buffer[i]);
	//		*/
	//		i++;
	//		if(i>ROWS)break;
	//		//buffer +=line+',';
	//		//list.push_back(line);
	//		//cout<<line<<endl;

	//	}
	//	infile.close();
	//}else{
	//	cout<<"not opened"<<endl;
	//}

	////char tmp[MAX_BUF_LEN] = "43735173856029611568442515340040338973765522024252082316032076385986617053089886752926708989233889578831940845942385592153895942552156209392481325308186780691620385855198994821671794143517814662528038016041565888708512232513867588340210126188506600216223286142866839767691175010591527471406190716529361189423";
	////printf("%s\n",tmp);
	///*for(int i = 0; i < 2000; i++){
	//	printf("%s\n", buffer[i]);
	//}*/
	//int* incoming= new int[LIMIT];
	//for (int i = 0; i < LIMIT; i++)
	//{
	//	incoming[i]=0;
	//}
	////cout<<i<<":"<<buffer[4] <<endl;
	////hammingDistance(eid, buffer,incoming,0,LIMIT, ROWS*ATTRS,ROWS);
	//euclidieanDistance(eid, buffer,incoming,0,LIMIT, ROWS*ATTRS,ROWS);
	//for (int i = 0; i < LIMIT; i++)
	//{
	//	printf("%d\n", incoming[i]);
	//}
	//printf("Ended\n");
	
	// Destroy the enclave when all Enclave calls finished.
	if(SGX_SUCCESS != sgx_destroy_enclave(eid)){
		cout<<"Cannot destroy Enclave"<<endl;
		return -1;
	}
	//std::getchar();
	return 0;
}

