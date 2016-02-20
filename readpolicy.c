/**
 * Author : Damien Gros
 * Mail : gros.damien@gmail.com
 * Read a SELinux binary policy and convert into a neutral language
 * Based on checkpolicy/tests/dispol.c
 * From Jeremy Briffaut
 **/

#include "readpolicy.h"

void PrintUserRolesTypes(FILE * fp)
{
        Users_Roles *head_user = list_user;
        int i=0, k=0;

        if(head_user == NULL)
        {
                fprintf(fp,"List NULL\n");
        }

        while(head_user->Next != NULL )
        {
                fprintf(fp,"### %s %i--%i { \n", head_user->user, head_user->low, head_user->hight);
                for(i=0; i<head_user->size; i++)
                {
                        fprintf(fp,"\t\t %s ( ", head_user->roles[i]->role);
                        for(k=0; k<head_user->roles[i]->size;k++)
                        {
                                fprintf(fp,"%s ", head_user->roles[i]->types[k]);
                        }
                        fprintf(fp," )\n");
                }
                fprintf(fp,"}\n");
                head_user=head_user->Next;
        }
}


Roles_Types *Add_item_RT(Roles_Types *list_users, char *role, char *types, FILE *fp)
{
	if(list_users == NULL)
	{	
		fprintf(fp, "Error add roles items, current list == NULL\n");
		return NULL;	
	}
	
    Roles_Types *roles_new =  malloc(sizeof(struct _roles_types_));
	
	if(roles_new == NULL)
	{	
		fprintf(fp, "Error add roles items, new Liste == NULL\n");
		return NULL;	
	}
	
    if(role != NULL)
        roles_new->role = role;

    return roles_new;
}


Users_Roles *Add_item(Users_Roles *list_current, char *users, char *roles, int mls_low, int mls_hight, FILE *fp)
{
	if(list_current == NULL)
	{	
		fprintf(fp, "Error add users items, current list == NULL\n");
		return NULL;	
	}
	
    Users_Roles *users_new =  malloc(sizeof(struct _users_roles_));
	
	if(users_new == NULL)
	{	
		fprintf(fp, "Error add users items, new Liste == NULL\n");
		return NULL;	
	}
	
	users_new->Next = list_current;
    if(users != NULL)
        users_new->user = users;
       
    users_new->low = mls_low;
    users_new->hight = mls_hight;
    return users_new;
}


void Usage()
{
	printf("Usage : readpolicy binary_policy file_contexts\n");
}

int render_access_mask(uint32_t mask, avtab_key_t * key, policydb_t * p,FILE * fp, TE_Rule * current)
{
	char *perm;
	perm = sepol_av_to_string(p, key->target_class, mask);
	if (perm)
    {
        current->access_rule =  malloc(strlen(perm)+1);

        strncpy(current->access_rule, perm, strlen(perm));
        current->access_rule[strlen(perm)]= '\0';
    }	
	return 0;
}

int render_type(uint32_t type, policydb_t * p, FILE * fp)
{
	fprintf(fp, "%s", p->p_type_val_to_name[type - 1]);
	return 0;
}

int render_key(avtab_key_t * key, policydb_t * p, FILE * fp, TE_Rule * current)
{
	char *stype, *ttype, *tclass ;
	stype = p->p_type_val_to_name[key->source_type - 1];
	ttype = p->p_type_val_to_name[key->target_type - 1];
	tclass = p->p_class_val_to_name[key->target_class - 1];
	if (stype && ttype)
    {
            current->stype = malloc(sizeof(stype));
            current->stype = stype;
            current->ttype = malloc(sizeof(ttype));
            current->ttype = ttype; 
            current->tclass = malloc(sizeof(tclass));
            current->tclass = tclass;
    }
	else if (stype)
		fprintf(fp, "# %s %u : %s\n ", stype, key->target_type, tclass);
	else if (ttype)
		fprintf(fp, "%u %s : %s ", key->source_type, ttype, tclass);
	else
		fprintf(fp, "%u %u : %s ", key->source_type, key->target_type,
				tclass);
	return 0;
}


void makeTrans(avtab_key_t * key, policydb_t * p, avtab_datum_t *datum)
{
        int  i, k;
        char *stype, *ttype, *tclass, *data ;
        stype = p->p_type_val_to_name[key->source_type - 1];
        ttype = p->p_type_val_to_name[key->target_type - 1];
        tclass = p->p_class_val_to_name[key->target_class - 1];
        data = p->p_type_val_to_name[datum->data - 1];
        
        if(strcmp(tclass,"process") == 0)
        {
                Users_Roles * head_users = list_user;

                while(head_users->Next != NULL)
                {
                        for(i=0; i<head_users->size; i++)
                        {
                                int pres = 0;
                                for(k=0; k<head_users->roles[i]->size;k++)
                                {
                                        if(strcmp(head_users->roles[i]->types[k], data)==0)
                                        {
                                                pres = 1;
                                                break;
                                        }
                                }
                                if(pres ==  0)
                                {
                                        head_users->roles[i]->types[head_users->roles[i]->size] = data;
                                        head_users->roles[i]->size = head_users->roles[i]->size +1;
                                }
                        }
                        head_users=head_users->Next;
                }
        }
        else
        {
                Object_Context * head_context =  object_context;
                while(head_context->Next != NULL)
                {
                        if(strcmp(head_context->type, ttype)==0)
                                return;
                        head_context=head_context->Next;
                }
               
                Users_Roles * head_users = list_user;

                while(head_users->Next != NULL)
                {
                        for(i=0; i<head_users->size; i++)
                        {
                                int pres = 0;
                                for(k=0; k<head_users->roles[i]->size;k++)
                                {
                                        if(strcmp(head_users->roles[i]->types[k], stype)==0)
                                        {
                                                pres = 1;
                                                break;
                                        }
                                }
                                if(pres ==  1)
                                {
                                        char temp[512];
                                        bzero(temp, 512);
                                        sprintf(temp,"%s:object_r:%s:s%i-s%i:c0:c1023", head_users->user, ttype, head_users->low, head_users->hight);
                                        object_context = AddToStructure(object_context,temp);
                                }
                        }
                        head_users=head_users->Next;
                }
        }
}

TE_Rule * PrintAV(avtab_key_t * key, avtab_datum_t * datum, 
                policydb_t * p, FILE * fp, TE_Rule * rules_current)
{

        if (key->specified & AVTAB_AV) {
                TE_Rule * fill_rule = malloc(sizeof(struct _te_rule_));
                if(fill_rule == NULL) return rules_current;

                fill_rule->Next = rules_current;

                if (key->specified & AVTAB_ALLOWED) {
                        render_key(key, p, fp, fill_rule);
                        render_access_mask(datum->data, key, p, fp, fill_rule);
	                    return fill_rule;
                }
                if (key->specified & AVTAB_AUDITALLOW) {
                        render_key(key, p, fp, fill_rule);
                        render_access_mask(datum->data, key, p, fp,fill_rule);
	                    return fill_rule;
                }
                if (key->specified & AVTAB_AUDITDENY) {
	                    return rules_current;
                }
        } else if (key->specified & AVTAB_TYPE) {
                if (key->specified & AVTAB_TRANSITION) {
                        makeTrans(key, p, datum);
                        return rules_current;
                }
                if (key->specified & AVTAB_MEMBER) {
                        return rules_current;
                }
                if (key->specified & AVTAB_CHANGE) {
                        makeTrans(key, p, datum);
                        return rules_current;
                }
        } else {
                fprintf(fp, "     ERROR: no valid rule type specified\n");
                return rules_current;
        }
        return rules_current;
}

void PrintPol(avtab_t * a, policydb_t * p, FILE * fp)
{
	unsigned int i;
	avtab_ptr_t cur;
	avtab_t expa;

	if (avtab_init(&expa))
		return;
	if (expand_avtab(p, a, &expa)) {
		avtab_destroy(&expa);
		return;
	}	

	int j=0,k=0;//s,l=0;
	char *U;
	char *R;
    list_user = malloc(sizeof (struct _users_roles_));

	user_datum_t **udt = p->user_val_to_struct;
	role_datum_t **rdt = p->role_val_to_struct;
	
	ebitmap_t role,type;

	int sens_low, sens_hight;
    int count_1 = 0, count_2=0;
	for (i = 0; i < policydb.p_users.nprim; i++) {
		role = udt[i]->roles.roles;
		U = policydb.p_user_val_to_name[udt[i]->s.value - 1];
	
		sens_hight = udt[i]->exp_range.level[1].sens-1;
		sens_low = udt[i]->exp_range.level[0].sens-1;

        // Ajout de l'id dans la liste, avec sa sensibilite
        if(U != NULL)
             list_user = Add_item(list_user,U,NULL,sens_low,sens_hight,fp);

        for (j = 0; j < role.highbit; j++){
                if (ebitmap_get_bit(&role, j) == 1) {
                        R = policydb.p_role_val_to_name[j];
                        Roles_Types *roles_new =  malloc(sizeof(struct _roles_types_));
                        roles_new->role = R;
                        type = rdt[j]->types.types;

                        for (k = 0; k < type.highbit; k++){
                                if (ebitmap_get_bit(&type, k) == 1) {
                                        char * t_name = policydb.p_type_val_to_name[k];
                                        roles_new->types[count_2] = t_name;
                                        count_2 = count_2 + 1;
                                }
                        }
                        roles_new->size = count_2;
                        list_user->roles[count_1]=roles_new;
                        count_2 = 0;
                        count_1++;
                }
                list_user->size = count_1;
        }
        count_1 = count_2 = 0;
    }

    PrintUserRolesTypes(fp);
    makeSCO(fp);

    rule_te = malloc(sizeof(struct _te_rule_));
    if(rule_te == NULL) return;
    for (i = 0; i < expa.nslot; i++) {
		for (cur = expa.htable[i]; cur; cur = cur->next) {
			rule_te = PrintAV(&cur->key, &cur->datum, p, fp, rule_te);
		}
    }
	avtab_destroy(&expa);
}


int count_rule=0;
void PrintPigaPol(avtab_t * a, policydb_t * p, FILE * fp, Users_Roles *current_users)
{
        unsigned int i,k=0, l=0, m=0;

        Object_Context * head_object = object_context;

        head_object= head_object->Next;

        if(current_users ==  NULL) return;
        if(head_object ==  NULL) return;

        for(i=0; i<current_users->size; i++)
        {
                for(k=0; k<current_users->roles[i]->size;k++)
                {
                        TE_Rule * head_te = rule_te;
                        fprintf(fp,"%s:%s:%s\n",current_users->user, current_users->roles[i]->role, current_users->roles[i]->types[k]);

                        while(head_te->Next != NULL)
                        {
                                if(strcmp(head_te->stype,  current_users->roles[i]->types[k])==0 )
                                {
                                        TE_Rule * list_te = rule_te;
                                        int write = 0;
                                        while(list_te->Next != NULL)
                                        {
                                                if(strcmp(head_te->stype,list_te->stype) == 0)
                                                {
                                                        if(write ==0)
                                                        {
                                                                fprintf(fp,"\t%s\n", list_te->ttype);
                                                                write =1;
                                                        }
                                                        fprintf(fp,"\t\t\t%s {%s };\n",list_te->tclass, list_te->access_rule);
                                                }
                                                list_te = list_te->Next;
                                        }
                                         write = 0;
                                }
                                head_te=head_te->Next;
                        }
                }
        }
}
/**
 * Main function
 *
 **/

int main(int argc, char **argv)
{
	FILE *out_fp = stdout;
	int fd, ret;
	struct stat sb;
	void *map;
	struct policy_file pf;

	
	if(argc != 3)
	{
		Usage();
		return -1;
	}
	fd = open(argv[1], O_RDONLY);
	if (fd < 0) {
		fprintf(stderr, "Can't open '%s':  %s\n",
				argv[1], strerror(errno));
		exit(1);
	}
	if (fstat(fd, &sb) < 0) {
		fprintf(stderr, "Can't stat '%s':  %s\n",
				argv[1], strerror(errno));
		exit(1);
	}
	map =
		mmap(NULL, sb.st_size, PROT_READ | PROT_WRITE, MAP_PRIVATE, fd, 0);
	if (map == MAP_FAILED) {
		fprintf(stderr, "Can't map '%s':  %s\n",
				argv[1], strerror(errno));
		exit(1);
	}

	/* read the binary policy */

	policy_file_init(&pf);
	pf.type = PF_USE_MEMORY;
	pf.data = map;
	pf.len = sb.st_size;
	policydb.mls= 1;
	if (policydb_init(&policydb)) {
		fprintf(stderr, "%s:  Out of memory!\n", argv[0]);
		exit(1);
	}
	ret = policydb_read(&policydb, &pf, 1);
	if (ret) {
		fprintf(stderr,
				"%s:  error(s) encountered while parsing configuration\n",
				argv[0]);
		exit(1);
	}


	PrintPol(&policydb.te_avtab, &policydb, out_fp);
    Users_Roles * cur = list_user;
    while(cur->Next != NULL)
    {
                          PrintPigaPol(&policydb.te_avtab, &policydb, out_fp, cur);
                          cur = cur->Next;

    }
        printf("%i \n", count_rule);
    close(fd);
	return 1;
}
