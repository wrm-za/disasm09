/* BUG report 2002-09-16

   does not handle long branches properly

*/

#include "stdio.h"
#include "ctype.h" /* for isprint() macro used in hexdump */

struct mnemonic {
  /* the index is the decimal opcode */
  char opcode[6];
  int mode;
} mn[256];

struct ext_mnemonic {
  /* the index is moot - search for the opcode value */
  unsigned int op_val;
  char opcode[6];
  int mode;
} xmn[47];

char reglist[16][3] = {{'D',' ','\0'},
		       {'X',' ','\0'},
		       {'Y',' ','\0'},
		       {'U',' ','\0'},
		       {'S',' ','\0'},
		       {'P','C','\0'},
		       {'?','?','\0'},
		       {'?','?','\0'},
		       {'A',' ','\0'},
		       {'B',' ','\0'},
		       {'C','C','\0'},
		       {'D','P','\0'},
		       {'?','?','\0'},
		       {'?','?','\0'},
		       {'?','?','\0'},
		       {'?','?','\0'}};

char indxreg[4][2] = {{'X','\0'},
		      {'Y','\0'},
		      {'U','\0'},
		      {'S','\0'}};

int initmn()
{
  int i,j;
  FILE *fp;
  int ok;
  char s[80];

  ok = 0;
  if ((fp = fopen("disasm09.txt","r")) == NULL) {
    printf("Cannot open DISASM09.TXT\n");
    ok = 1;
  }
  i = 0;
  while(!feof(fp)) {
    if(fgets(s,80,fp)) {
      for (j=0;j<6;j++) {
	mn[i].opcode[j] = s[j];
	if (s[j] == ' ') {
	  mn[i].opcode[j] = '\0';
	  mn[i].mode = s[j+1]; /* ONE space ONLY allowed */
	  j = 6;
	}
      }
      /*
      printf("%2X %s %c\n",i,mn[i].opcode,mn[i].mode);
      */
      i++;
    }
  }
  if (i != 256) {
    printf("ONLY %i OPCODES READ!\n",i);
    ok = 2;
  }

  if (fclose(fp)) {
    printf("Error closing DISASM09.TXT!\n");
    ok = 3;
  }
  return ok;
}

int initxmn()
{
  int i,j;
  FILE *fp;
  int ok;
  char s[80];
  char os[5];

  ok = 0;
  if ((fp = fopen("disasm09.txx","r")) == NULL) {
    printf("Cannot open DISASM09.TXX\n");
    ok = 1;
  }
  i = 0;
  while(!feof(fp)) {
    if(fgets(s,80,fp)) {
      for (j=0;j<4;j++) {
	os[j] = s[j]; /* opcode # the fisrt 4 bytes */
      }
      os[4] = '\0';
      xmn[i].op_val = atoi(os);
      for (j=0;j<6;j++) {
	xmn[i].opcode[j] = s[j+5]; /* s[4] a space */
	if (s[j] == ' ') {
	  xmn[i].opcode[j] = '\0';
	  xmn[i].mode = s[j+6]; /* ONE space ONLY allowed */
	  j = 6;
	}
      }
      /**
      printf("%2X %s %c\n",xmn[i].op_val,xmn[i].opcode,xmn[i].mode);
      **/
      i++;
    }
  }
  if (i != 47) {
    printf("ONLY %i OPCODES READ!\n",i);
    ok = 2;
  }

  if (fclose(fp)) {
    printf("Error closing DISASM09.TXT!\n");
    ok = 3;
  }
  return ok;
}


main(argc, argv)
int argc;
char *argv[];
{
  FILE *fp;
  int i,j;
  int op, opx, ad, bt, ea, am, im, rr;
  int end_ad = 0xffff; /* default */
  int filestart;
  int exok;
  char opcode[6];
  int mode;
  char infilename[80], outfilename[80];
  int infile, outfile, hexdump, fileflag, disasmflag;
  char hs[17];

  clrscr();
  printf("\n6809 Disassembler.\n");
  printf("By W. de Waal 1990/91\n");
  printf("C source code available.\n");
  printf("Data areas still to be implemented. (simulate with -ea)\n");
  printf("\nCommand line arguments :\n");
  printf("-if <inputfile>\n");
  printf("-of <outputfile>\n");
  printf("-hd hex dump\n");
  printf("-fo <address> Hex file offset\n");
  printf("-sa <address> Hex disasm start address\n");
  printf("-ea <address> Hex disasm end address (default $FFFF)\n");

  /* -if <inputfile> */
  /* -of <outputfile> */
  /* -hd -- hexdump (disasm default) */
  /* -fa <address> -- file start address */
  /* -sa <address> -- disasm start address ( > file start address ) */
  /* -ea <address> -- disasm end address (=0xffff default) */
  infile = 0;
  outfile = 0;
  hexdump = 0;
  fileflag = 0;
  disasmflag = 0;

  for (i=0;i<(argc-1);i++) {
    if (strcmp(argv[i],"-if")==0) {
      strcpy(infilename,argv[i+1]);
      infile = 1;
      printf("Input file <%s>\n",infilename);
    }
    if (strcmp(argv[i],"-of")==0) {
      strcpy(outfilename,argv[i+1]);
      outfile = 1;
      printf("Output file <%s> (not implemented)\n",outfilename);
    }
    if (strcmp(argv[i],"-fo")==0) {
      sscanf(argv[i+1],"%x",&filestart);
      fileflag = 1;
      printf("File starts at $%04X\n",filestart);
    }
    if (strcmp(argv[i],"-sa")==0) {
      sscanf(argv[i+1],"%x",&ad);
      disasmflag = 1;
      printf("Disasm starts at $%04X\n",ad);
    }
    if (strcmp(argv[i],"-ea")==0) {
      sscanf(argv[i+1],"%x",&end_ad);
      printf("Disasm ends at $%04X\n",end_ad);
    }
    if (strcmp(argv[i],"-hd")==0) {
      hexdump = 1;
      printf("Hex Dump.\n");
    }
  }
  if (strcmp(argv[argc-1],"-hd")==0) {
    hexdump = 1;
  }
  printf("\n");
  if (infile==0) {
    printf("Input file : ");
    scanf("%s",infilename);
  }
  if (fileflag==0) {
    printf("File starts at (hex) : ");
    scanf("%x",&filestart);
  }
  if (disasmflag==0) {
    printf("Disasm from (hex) : ");
    scanf("%x",&ad);
  }
  if (ad < filestart) {
    printf("Cannot disasm code not in file!\n");
    printf("File starts at $%04X\n",filestart);
    printf("Disasm starts at $04X\n",ad);
    exit(3);
  }

  if (initmn() !=0) exit(1);
  if (initxmn() != 0) exit(2);
  printf("start\n");
  if ((fp = fopen(infilename,"rb")) == NULL) {
    printf("Cannot open input file <%s>\n",infilename);
    exit(3);
  }
  fseek(fp,(ad-filestart),SEEK_SET);
  if (hexdump == 1) {
    /* hex dump routine */
    hs[16] = '\0';
    while(!feof(fp) && (ad<=end_ad)) {
      printf("%04X: ",ad);
      for (i=0;i<16;i++) {
	op = fgetc(fp);
	if (feof(fp) || ((ad+i)>end_ad)) {
	  hs[i] = '\0';
	  for (j=0;j<(16-i);j++) printf("   "); /* pad line */
	  i = 16;
	} else {
	  if (isprint(op)) {
	    hs[i] = op;
	  } else {
	    /* non printing character */
	    hs[i] = '.'; /* change this if you don't like it */
	  }
	  printf("%02X ",op);
	}
      }
      ad += 16;
      printf(" %s\n",hs);
    }
  } else {
    /* disassemble */
    while (!feof(fp) && (ad<=end_ad)) {
      /* loop starts here */
      printf("%04X:",ad);
      op = fgetc(fp); ad++;
      if ((op == 0x10) | (op == 0x11)) {
	/* do special instruction */
	opx = fgetc(fp); ad++;
	op = op*256 + opx;
	printf(" %04X",op);
	exok = 0;
	for (i=0;i<47;i++) {
	  if (xmn[i].op_val == op) {
	    strcpy(opcode,xmn[i].opcode);
	    mode = xmn[i].mode;
	    exok = 1;
	  }
	}
	if (exok == 0) {
	  strcpy(opcode,"???");
	  mode = 'V';
	}
      } else { /* not special instr */
	/* get op + mnemonic for standard instruction */
	printf(" %02X  ",op);
	strcpy(opcode,mn[op].opcode);
	mode = mn[op].mode;
      }

      /* printf(">>%c<<",mode); */

      switch(mode) {
	case 'H' : printf("         %-6s\n",opcode);
		   break;
	case 'D' : bt = fgetc(fp); ad++;
		   printf(" %02X      %-6s $%02X\n",bt,opcode,bt);
		   break;
	case 'R' : ea = fgetc(fp); ad++;
		   printf(" %02X      %-6s ",ea,opcode);
		   if (ea > 128) ea -= 256;
		   ea += ad;
		   printf("$%04X\n",ea);
		   break;
	case 'M' : bt = fgetc(fp); ad++;
		   printf(" %02X      %-6s #$%02X\n",bt,opcode,bt);
		   break;
	case 'E' : ea = fgetc(fp); ad++;
		   bt = fgetc(fp); ad++;
		   ea = 256*ea + bt;
		   printf(" %04X    %-6s $%04X\n",ea,opcode,ea);
		   break;
	case 'V' : printf("         ???    (invalid opcode)\n");
		   break;
	case 'X' : bt = fgetc(fp); ad++;
		   if (bt < 128) {
		     /* 5 bit offset */
		     rr = bt/32;
		     ea = bt - 32*rr;
		     if (ea > 15) ea -= 32;
		     printf(" %02X      %-6s %i,%-6s\n",
		       bt,opcode,ea,indxreg[rr]);
		   } else { /* bt >= 128 */
		     printf(" %02X",bt);
		     bt -= 128;
		     rr = bt/32;
		     am = bt - 32*rr;
		     /*****
		     printf(">>rr = %i am = %i<<",rr,am);
		     *****/
		     if (am > 15) {
		       im = 1;
		       am -= 16;
		     } else {
		       im = 0;
		     }
		     switch (am) {
		       case 0 : /* auto inc by 1 */
				if (im == 0) {
				  printf("      %-6s ,%s+",
				    opcode,indxreg[rr]);
				} else {
				  printf("      %-6s (,%s+)",
				    opcode,indxreg[rr]);
				}
				break;
		       case 1 : /* auto inc by 2 */
				if (im == 0) {
				  printf("      %-6s ,%s++",
				    opcode,indxreg[rr]);
				} else {
				  printf("      %-6s (,%s++)",
				    opcode,indxreg[rr]);
				}
				break;
		       case 2 : /* auto dec by 1 */
				if (im == 0) {
				  printf("      %-6s ,-%s",
				    opcode,indxreg[rr]);
				} else {
				  printf("      %-6s (,-%s)",
				    opcode,indxreg[rr]);
				}
				break;
		       case 3 : /* auto dec by 2 */
				if (im == 0) {
				  printf("      %-6s ,--%s",
				    opcode,indxreg[rr]);
				} else {
				  printf("      %-6s (,--%s)",
				    opcode,indxreg[rr]);
				}
				break;
		       case 4 : /* zero offset */
				if (im == 0) {
				  printf("      %-6s ,%s",
				    opcode,indxreg[rr]);
				} else {
				  printf("      %-6s (,%s)",
				    opcode,indxreg[rr]);
				}
				break;
		       case 5 : /* acc b offset */
				if (im == 0) {
				  printf("      %-6s B,%s",
				    opcode,indxreg[rr]);
				} else {
				  printf("      %-6s (B,%s)",
				    opcode,indxreg[rr]);
				}
				break;
		       case 6 : /* acc a offset */
				if (im == 0) {
				  printf("      %-6s A,%s+",
				    opcode,indxreg[rr]);
				} else {
				  printf("      %-6s (A,%s+)",
				    opcode,indxreg[rr]);
				}
				break;
		       case 7 : /* not valid */
				printf("      ?????");
				break;
		       case 8 : /* 8-bit offset */
				bt = fgetc(fp); ad++;
				ea = bt;
				if (ea > 127) ea -= 256;
				if (im == 0) {
				  printf(" %02X   %-6s %i,%s",
				    bt,opcode,ea,indxreg[rr]);
				} else {
				  printf(" %02X   %-6s (%i,%s)",
				    bt,opcode,ea,indxreg[rr]);
				}
				break;
		       case 9 : /* 16-bit offset */
				ea = fgetc(fp); ad++;
				bt = fgetc(fp); ad++;
				bt = 256*ea + bt;
				ea = bt;
				/***** possible fuck up here -
				  ea is type int so leave conversion out ?
				if (ea > 32767) ea -= 32768;
				***/
				if (im == 0) {
				  printf(" %04X  %-6s %i <== check code ,%s",
				    bt,opcode,ea,indxreg[rr]);
				} else {
				  printf(" %04X  %-6s (%i <== check code ,%s)",
				    bt,opcode,ea,indxreg[rr]);
				}
				break;
		       case 10 : /* invalid post-byte */
				 printf("  ??? (debug - X case 10)");
				 break;
		       case 11 : /* offset by d */
				 if (im == 0) {
				   printf("      %-6s D,%s",
				     opcode,indxreg[rr]);
				 } else {
				   printf("      %-6s (D,%s)",
				     opcode,indxreg[rr]);
				 }
				 break;
		       case 12 : /* 8-bit pcr */
				 bt = fgetc(fp); ad++;
				 ea = bt;
				 if (ea > 127) ea -= 256;
				 if (im == 0) {
				   printf(" %02X %-6s %i,PCR",
				     bt,opcode,ea);
				 } else {
				   printf(" %02X %-6s (%i,PCR)",
				     bt,opcode,ea);
				 }
				 break;
		       case 13 : /* 16-bit pcr */
				 ea = fgetc(fp); ad++;
				 bt = fgetc(fp); ad++;
				 bt = 256*ea + bt;
				 ea = bt;
				 if (ea > 127) ea -= 256;
				 if (im == 0) {
				   printf(" %04X %-6s %i,PCR",
				     bt,opcode,ea);
				 } else {
				   printf(" %04X %-6s (%i,PCR)",
				     bt,opcode,ea);
				 }
				 break;
		       case 14 : /* invalid */
				 printf("     ??? (debug - X case 14)");
				 break;
		       case 15 : /* indirect address */
				 ea = fgetc(fp); ad++;
				 bt = fgetc(fp); ad++;
				 bt = 256*ea + bt;
				 ea = bt;
				 if (ea > 127) ea -= 256;
				 if (im == 0) {
				   printf(" %04X %-6s $%04X",
				     bt,opcode,bt);
				 } else {
				   printf(" %04X %-6s ($%04X)",
				     bt,opcode,bt);
				 }
				 break;
		       default : break;
		     }
		     printf("\n");
		   }
		   break;
	case '1' : bt = fgetc(fp); ad++;
		   printf(" %02X      %-6s ",bt,opcode);
		   printf("%2s,%2s\n",reglist[bt/16],reglist[bt-16*(bt/16)]);
		   break;
	case '2' : ea = fgetc(fp); ad++;
		   printf(" %02X      %-6s ",ea,opcode);
		   if (ea >= 128) {
		     printf("PC,");
		     ea -= 128;
		   }
		   if (ea >= 64) {
		     printf("U,");
		     ea -= 64;
		   }
		   if (ea >= 32) {
		     printf("Y,");
		     ea -= 32;
		   }
		   if (ea >= 16) {
		     printf("X,");
		     ea -= 16;
		   }
		   if (ea >= 8) {
		     printf("DP,");
		     ea -= 8;
		   }
		   if (ea >= 4) {
		     printf("B,");
		     ea -= 4;
		   }
		   if (ea >= 2) {
		     printf("A,");
		     ea -= 2;
		   }
		   if (ea >= 1) printf("C,");
		   printf("\n");
		   break;
	case 'L' : ea = fgetc(fp); ad++;
		   bt = fgetc(fp); ad++;
		   ea = 256*ea + bt;
		   printf(" %04X    %-6s ",ea,opcode);
		   /* this might be ea > 32768 !!! */
		   if (ea > 32767) ea -= 65536;
		   printf("$%04X\n",ea+ad);
		   break;
	case '3' : ea = fgetc(fp); ad++;
		   bt = fgetc(fp); ad++;
		   ea = 256*ea + bt;
		   printf(" %04X    %-6s #$%04X\n",ea,opcode,ea);
		   break;
	default : break;
      } /* switch(mode) */
    } /* while (!feof(fp)) */
  } /* if hexdump else disasm */
  if (fclose(fp)) {
    printf("Error closing input file\n");
    exit(3);
  }

  printf("end.\n");
}


