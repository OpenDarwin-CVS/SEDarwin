#import "LabelChooser.h"

@implementation LabelChooser

extern int          global_argc;
extern const char **global_argv;

- (void)awakeFromNib
{
    [window setLevel:NSPopUpMenuWindowLevel ];
}

- (IBAction)ui_ok:(id)sender
{
    NSCell *c = [list selectedCell];
    if (c)
    {
        printf ("%s\n", [ [c stringValue] cString]);
        exit(0);
    }
}

- (int)browser:(NSBrowser *)sender numberOfRowsInColumn:(int)column
{
    return column ? 0 : global_argc;
}

- (void)browser:(NSBrowser *)sender willDisplayCell:(id)cell atRow:(int)row column:(int)column
{
    [cell setLeaf:true];
    [cell setStringValue: [NSString stringWithCString: global_argv[row]]];
    if (row + column == 0)
        [list selectRow:0 inColumn:0];
}
@end
