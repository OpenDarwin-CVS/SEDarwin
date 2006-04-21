
#import "LabelDialog.h"
#import <Cocoa/Cocoa.h>
#import <sys/mac.h>
//#import <selinux/sebsd.h>
#import <selinux/selinux.h>

const char *filename;
char *initial;

char **users, **roles, **types;
size_t nusers, nroles, ntypes;

static void addstring (char **ar, size_t *n, char *in)
{
    int i;
    for (i = 0; i < *n; i++)
        if (!strcmp (ar[i], in))
            return;
    ar[(*n)++] = in;
}

static void splitcon (char *po, char **user, char **role, char **type)
{
    char *p = po;
    while (*p != ':') p++;
    *p = 0; p++;
    *user = po;
    po = p;
    while (*p != ':') p++;
    *p = 0; p++;
    *role = po;
    *type = p;
}

int main (int argc, const char *argv[])
{
    if (argc > 2)
    {
        filename = argv[2];

        mac_t label;
    
        if (mac_prepare (&label, "sebsd"))
            exit (1);
        if (mac_get_link (filename, label) || mac_to_text (label, &initial))
            exit (1);
        
        initial += 6;
    }
    else
        filename = NULL;

    char **filelabels;
    size_t nfilelabels;
    char *seccon;
    
    if (getcon(&seccon)) {
	fprintf(stderr, "Failed to get the current security context\n");
        exit(1);
    }
    if (security_get_file_contexts (seccon, &filelabels, &nfilelabels))
//    if (security_get_file_contexts (getseccontext(), &filelabels, &nfilelabels))
        exit (1);
    free(seccon);
    users = (char **) malloc (sizeof (char *) * (1+nfilelabels));
    roles = (char **) malloc (sizeof (char *) * (1+nfilelabels));
    types = (char **) malloc (sizeof (char *) * (1+nfilelabels));
    nusers = nroles = ntypes = 0;
    int i;
    for (i = 0; i < nfilelabels; i++)
    {
        char *user, *role, *type;
        splitcon (filelabels[i], &user, &role, &type);
        addstring (users, &nusers, user);
        addstring (roles, &nroles, role);
        addstring (types, &ntypes, type);
    }

    return NSApplicationMain(argc, argv);
}

@implementation LabelDialog

- (void)awakeFromNib
{
    if (filename == NULL)
    {
        NSOpenPanel *o = [NSOpenPanel openPanel];
        [o setCanChooseDirectories:YES];
        int oresult = [o runModalForDirectory:NSHomeDirectory() file:nil types:nil];
        if (oresult != NSOKButton)
            exit (1);
        NSArray *fa = [o filenames];
        if ([fa count] < 1)
            exit (1);
        filename = [ [fa objectAtIndex:0] cString ];
        
        mac_t label;
    
        if (mac_prepare (&label, "sebsd"))
            exit (1);
        if (mac_get_link (filename, label) || mac_to_text (label, &initial))
            exit (1);
        initial += 6;
    }

    [window setTitle: [NSString stringWithCString: filename]];
    [window setLevel:NSPopUpMenuWindowLevel ];

    char *iuser, *irole, *itype;
    splitcon (initial, &iuser, &irole, &itype);
    addstring (users, &nusers, iuser);
    addstring (roles, &nroles, irole);
    addstring (types, &ntypes, itype);

    [menuu removeAllItems]; [menur removeAllItems]; [menut removeAllItems];
    int i;
    for (i = 0; i < nusers; i++)
        [menuu addItemWithTitle: [NSString stringWithCString: users[i]]];
    for (i = 0; i < nroles; i++)
        [menur addItemWithTitle: [NSString stringWithCString: roles[i]]];
    for (i = 0; i < ntypes; i++)
        [menut addItemWithTitle: [NSString stringWithCString: types[i]]];
        
    [menuu selectItemWithTitle: [NSString stringWithCString: iuser]];
    [menur selectItemWithTitle: [NSString stringWithCString: irole]];
    [menut selectItemWithTitle: [NSString stringWithCString: itype]];
    
    //[labeltext setStringValue: [NSString stringWithCString: initial]];
    [self ui_menus:nil];
}

- (IBAction)ui_cancel:(id)sender
{
    exit (1);
}

- (IBAction)ui_menus:(id)sender
{
    NSString *colon = @":";
    NSString *label = [[menuu titleOfSelectedItem] stringByAppendingString: 
        [colon stringByAppendingString: [[menur titleOfSelectedItem] stringByAppendingString:
            [colon stringByAppendingString: [menut titleOfSelectedItem]]]]];
    [labeltext setStringValue:label];
}

- (IBAction)ui_ok:(id)sender
{
    char *ltext = [[@"sebsd/" stringByAppendingString: [labeltext stringValue]] cString];
    mac_t label;
    if (mac_from_text (&label, ltext) ||
        mac_set_link (filename, label))
    {
        printf ("%s\n", ltext);
        perror (filename);
        exit (1);
    }
    exit (0);
}

@end
