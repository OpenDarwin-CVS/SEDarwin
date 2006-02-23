/* LabelChooser */

#import <Cocoa/Cocoa.h>

@interface LabelChooser : NSObject
{
    IBOutlet NSBrowser *list;
    IBOutlet NSPanel *window;
}
- (IBAction)ui_ok:(id)sender;
@end
