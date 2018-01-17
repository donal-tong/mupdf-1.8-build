#import <Foundation/Foundation.h>

#include "mupdf/fitz.h"

@interface MuDocRef : NSObject
{
@public
	fz_document *doc;
	bool interactive;
	char *filename;
}
-(id) initWithFilename:(char *)aFilename;
@end
