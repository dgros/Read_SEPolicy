#include "readpolicy.h"

void getContext(char * line)
{
        char * temp;
        if(line == NULL)
                return;
        temp = strstr(line, "system_u"); 
        if(temp != NULL)
        {
                temp[strlen(temp)-1] = '\0';
                ocontext[tab] = malloc(sizeof(char *)*256);
                strcpy( ocontext[tab], temp);
                tab++;
        }
}

Object_Context * AddToStructure(Object_Context * object, char * parsing)
{ 
        char * temporaire;
        char context_sec[512];
        int l=0;
        
        if(object == NULL) return NULL;
        if(parsing == NULL) return object;
        
        if(context_sec == NULL) return object;
        bzero(context_sec,512);
        for(l=0;l<strlen(parsing);l++)
                     context_sec[l] = parsing[l];
         context_sec[l] = '\0';
        
        
        temporaire =  strtok(parsing,":");
        temporaire =  strtok(NULL,":");
        temporaire =  strtok(NULL,":");

        Object_Context * head_context =  object;

        if(temporaire == NULL) return head_context;
        while(head_context->Next != NULL)
        {
                if(strcmp(head_context->type, temporaire)==0)
                {
                        return object; //head_context;
                }
                head_context=head_context->Next;
        }

        Object_Context * object_context_1 = malloc(sizeof(struct _object_context_));
        object_context_1->Next = object;
        
        object_context_1->type = malloc(strlen(temporaire) +1);
        strncpy(object_context_1->type, temporaire,strlen(temporaire)) ;
        object_context_1->type[strlen(temporaire)]= '\0';
        
        object_context_1->sec_context = malloc(strlen(context_sec) +1);
        strncpy(object_context_1->sec_context, context_sec,strlen(context_sec)) ;
        object_context_1->sec_context[strlen(context_sec)]= '\0';

        temporaire =  strtok(NULL,":");
        object_context_1->sens = malloc(strlen(temporaire));
        strncpy( object_context_1->sens, temporaire, strlen(temporaire));
        if((temporaire = strtok(NULL, ":")) != NULL)
        {
                object_context_1->c1 = malloc(strlen(temporaire));
                strncpy( object_context_1->c1, temporaire, strlen(temporaire));
                if((temporaire = strtok(NULL, ":")) != NULL)
                {
                        object_context_1->c2 = malloc(strlen(temporaire));
                        strncpy( object_context_1->c2, temporaire, strlen(temporaire));
                }
                else
                {
                        object_context_1->c2 = NULL;
                }
        }
        else
        {
                object_context_1->c1 = NULL;
                object_context_1->c2 = NULL;

        }

        return object_context_1;
}

void Tab_To_Structure()
{
        int j =0;
        object_context = malloc(sizeof(struct _object_context_));
        object_context->Next = NULL ;
        if(object_context == NULL)
                return;

        for(j = 0; j<tab+1; j++)
        {
                object_context = AddToStructure(object_context,ocontext[j]);
        }
}

void ParseFileContext()
{
        FILE * fc =NULL;

        fc = fopen("file_contexts", "r+");

        if(fc == NULL)
                return;

        char line [128]; 
        while ( fgets ( line, sizeof line, fc ) != NULL ) 
        {
                getContext(line); 
        }
        fclose ( fc);
}

void printContext()
{        
        Object_Context * head_context =  object_context;
        if(head_context == NULL )
        {
                printf("oupsss \n");
                return;
        }
        while(head_context->Next != NULL)
        {
                printf("%s \n", head_context->type);
                printf("AA %s \n", head_context->sec_context  );
                head_context= head_context->Next;
        }
}


void Gestion_Ocontext(FILE *fp)
{
        int p;
        ocontext_t *t;
        for (p = 0; p < OCON_NUM; p++) {
                t = (ocontext_t *) policydb.ocontexts[p];
                while (t) {
                        char *s = (char *) malloc((strlen(policydb.p_user_val_to_name[t->context[0].user - 1]) + strlen(policydb.p_role_val_to_name[t->context[0].role - 1]) + strlen(policydb.p_type_val_to_name[t->context[0].type - 1]) + 4) * sizeof(char));
                        sprintf(s, "%s:%s:%s", policydb.p_user_val_to_name[t->context[0].user - 1], 
                                        policydb.p_role_val_to_name[t->context[0].role - 1], 
                                        policydb.p_type_val_to_name[t->context[0].type - 1]);
                        if (strcmp(policydb.p_role_val_to_name[t->context[0].role - 1], "object_r") == 0) 
                        {
                                char temp[512];
                                sprintf(temp,"%s:s%i:c0:c1023", s, t->context[0].range.level[1].sens -1);
                                object_context = AddToStructure(object_context,temp);
                        }
                        t=t->next;
                }

        }

        genfs_t *g = policydb.genfs;
        while (g) {
                ocontext_t *t = (ocontext_t *) g->head;
                while (t) {
                        char *s = (char *) malloc((strlen(policydb.p_user_val_to_name[t->context[0].user - 1]) + strlen(policydb.p_role_val_to_name[t->context[0].role - 1]) + strlen(policydb.p_type_val_to_name[t->context[0].type - 1]) + 4) * sizeof(char));
                        sprintf(s, "%s:%s:%s", policydb.p_user_val_to_name[t->context[0].user - 1], 
                                        policydb.p_role_val_to_name[t->context[0].role - 1], 
                                        policydb.p_type_val_to_name[t->context[0].type - 1]);
                        char temp[512];
                        sprintf(temp,"%s:s%i:c0:c1023", s, t->context[0].range.level[1].sens -1);
                        object_context = AddToStructure(object_context,temp);

                        t = t->next;
                }
                g = g->next;
        }
}

void  makeSCO(FILE * fp)
{
        ParseFileContext();
        Tab_To_Structure();
        Gestion_Ocontext(fp);
}
