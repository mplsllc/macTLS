/*
 * ostls_text_encoding.c -- Text encoding stub for macTLSLib
 *
 * Provides stub implementations for TextEncoding functions required
 * by the Carbon SDK interface.
 */

#include <stddef.h>

/* Minimal types */
typedef unsigned long TextEncoding;
typedef unsigned long TextEncodingBase;
typedef unsigned long TextEncodingVariant;
typedef unsigned long TextEncodingFormat;
typedef unsigned long ScriptCode;
typedef unsigned long LangCode;
typedef unsigned long RegionCode;
typedef const unsigned char *ConstStr255Param;
typedef long OSStatus;
typedef unsigned long UniChar;
typedef unsigned long TextToUnicodeInfo;
typedef unsigned long UnicodeToTextInfo;
typedef unsigned long LogicalAddress;
typedef void *WindowPtr;
typedef void *Cursor;
typedef void *AEEventHandlerUPP;
typedef void *AEEventHandlerProcPtr;
typedef void *ScrapRef;
typedef unsigned long ScrapFlavorType;
typedef unsigned long Size;
typedef void *MenuHandle;

#define noErr 0

/* Stub implementations */
OSStatus UpgradeScriptInfoToTextEncoding(
    ScriptCode script,
    LangCode language,
    RegionCode region,
    ConstStr255Param fontname,
    TextEncoding *encoding)
{
    (void)script;
    (void)language;
    (void)region;
    (void)fontname;
    if (encoding) *encoding = 0;
    return noErr;
}

TextEncoding CreateTextEncoding(
    TextEncodingBase base,
    TextEncodingVariant variant,
    TextEncodingFormat format)
{
    (void)base;
    (void)variant;
    (void)format;
    return 0;
}

OSStatus CreateTextToUnicodeInfoByEncoding(
    TextEncoding encoding,
    TextToUnicodeInfo *info)
{
    (void)encoding;
    if (info) *info = 0;
    return noErr;
}

OSStatus ConvertFromTextToUnicode(
    TextToUnicodeInfo info,
    unsigned long source_len,
    const void *source,
    unsigned long control_flags,
    unsigned long offset_count,
    unsigned long *offset_array_out,
    unsigned long *offset_count_out,
    unsigned long *offset_array,
    unsigned long output_buf_len,
    unsigned long *source_read,
    unsigned long *unicode_len,
    UniChar *unicode_str)
{
    (void)info;
    (void)source_len;
    (void)source;
    (void)control_flags;
    (void)offset_count;
    (void)offset_array_out;
    (void)offset_count_out;
    (void)offset_array;
    (void)output_buf_len;
    (void)source_read;
    (void)unicode_len;
    (void)unicode_str;
    return noErr;
}

OSStatus DisposeTextToUnicodeInfo(TextToUnicodeInfo *info)
{
    (void)info;
    return noErr;
}

OSStatus CreateUnicodeToTextInfoByEncoding(
    TextEncoding encoding,
    UnicodeToTextInfo *info)
{
    (void)encoding;
    if (info) *info = 0;
    return noErr;
}

OSStatus ConvertFromUnicodeToText(
    UnicodeToTextInfo info,
    unsigned long unicode_len,
    const UniChar *unicode_str,
    unsigned long control_flags,
    unsigned long offset_count,
    unsigned long *offset_array_out,
    unsigned long *offset_count_out,
    unsigned long *offset_array,
    unsigned long output_buf_len,
    unsigned long *unicode_read,
    unsigned long *output_len,
    LogicalAddress output_str)
{
    (void)info;
    (void)unicode_len;
    (void)unicode_str;
    (void)control_flags;
    (void)offset_count;
    (void)offset_array_out;
    (void)offset_count_out;
    (void)offset_array;
    (void)output_buf_len;
    (void)unicode_read;
    (void)output_len;
    (void)output_str;
    return noErr;
}

OSStatus DisposeUnicodeToTextInfo(UnicodeToTextInfo *info)
{
    (void)info;
    return noErr;
}

OSStatus SetPortWindowPort(WindowPtr window)
{
    (void)window;
    return noErr;
}

Cursor GetQDGlobalsArrow(Cursor *cursor)
{
    (void)cursor;
    return 0;
}

OSStatus GetCurrentScrap(ScrapRef *scrap)
{
    (void)scrap;
    return noErr;
}

Size GetScrapFlavorSize(
    ScrapRef scrap,
    ScrapFlavorType flavor_type,
    Size *size)
{
    (void)scrap;
    (void)flavor_type;
    if (size) *size = 0;
    return noErr;
}

Size GetScrapFlavorData(
    ScrapRef scrap,
    ScrapFlavorType flavor_type,
    void *data_ptr,
    Size max_size,
    Size *actual_size)
{
    (void)scrap;
    (void)flavor_type;
    (void)data_ptr;
    (void)max_size;
    if (actual_size) *actual_size = 0;
    return noErr;
}

OSStatus ClearCurrentScrap(void)
{
    return noErr;
}

OSStatus PutScrapFlavor(
    ScrapRef scrap,
    ScrapFlavorType flavor_type,
    Size data_size,
    const void *data_ptr)
{
    (void)scrap;
    (void)flavor_type;
    (void)data_ptr;
    (void)data_size;
    return noErr;
}

OSStatus DisableMenuItem(MenuHandle menu, short item)
{
    (void)menu;
    (void)item;
    return noErr;
}

OSStatus EnableMenuItem(MenuHandle menu, short item)
{
    (void)menu;
    (void)item;
    return noErr;
}

AEEventHandlerUPP NewAEEventHandlerUPP(AEEventHandlerProcPtr proc)
{
    (void)proc;
    return 0;
}
