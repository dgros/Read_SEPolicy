#ifndef _READPOLICY_H
#define _READPOLICY_H

#include <sepol/policydb/policydb.h>
#include <sepol/policydb/avtab.h>
#include <sepol/policydb/services.h>
#include <sepol/policydb/conditional.h>
#include <sepol/policydb/expand.h>
#include <sepol/policydb/util.h>
#include <sepol/policydb/polcaps.h>
#include <getopt.h>
#include <assert.h>
#include <unistd.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/mman.h>
#include <errno.h>
#include <stdio.h>
#include <fcntl.h>


char * ocontext[2000];
int tab;//w:=0;

typedef struct _te_rule_ {
        struct _te_rule_ *Next;
        char * stype;
        char * ttype;
        char * tclass;
        char * access_rule;
} TE_Rule;

TE_Rule * rule_te;

TE_Rule * rule_te;// Liste chainee contenant les contextes objets
typedef struct _object_context_ {
        struct _object_context_ *Next;
        char * type;
        char * sec_context;
        char * sens;
        char * c1;
        char * c2;
} Object_Context;

Object_Context * object_context;// = NULL;

/**
  * La representation choisi se fait sous forme de graph, ayant pour noeud parent les user
  * Les enfants de ses noeuds sont les roles autorises pour ces users
  * Les petit-enfants sont les types associes aux roles
  **/

// Liste associant les types au roles
typedef struct _roles_types_ {
	char * role; 
	char *types[2000]; 
	int size;
} Roles_Types;

// Liste associant les user aux roles
typedef struct _users_roles_ {
    struct _users_roles_ *Next;
	char *user; //contient l'identite SELinux
	struct _roles_types_  * roles[20]; //contient les roles associes
	int low;
	int hight;
	int size;
} Users_Roles;

Users_Roles *list_user;// = NULL;

policydb_t policydb;

// Affiche comment utiliser le programme
void Usage();
void makeSCO(FILE *fp);
void PrintUserRolesTypes(FILE * fp);

Roles_Types *Add_item_RT(Roles_Types *list_users, char *role, char *types, FILE *fp);
Users_Roles *Add_item(Users_Roles *list_current, char *users, char *roles, int mls_low, int mls_hight, FILE *fp);

int render_access_mask(uint32_t mask, avtab_key_t * key, policydb_t * p,FILE * fp, TE_Rule *current);

int render_type(uint32_t type, policydb_t * p, FILE * fp);
int render_key(avtab_key_t * key, policydb_t * p, FILE * fp, TE_Rule * current);

TE_Rule * PrintAV(avtab_key_t * key, avtab_datum_t * datum, policydb_t * p, FILE * fp, TE_Rule * _rules_te);

void PrintPol(avtab_t * a, policydb_t * p, FILE * fp);
void getContext(char * line);

Object_Context * AddToStructure(Object_Context * object, char * parsing);

void Tab_To_Structure();
void ParseFileContext();

void printContext();
void Gestion_Ocontext(FILE *fp);




#endif
