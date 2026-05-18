/*
 * MacSSLTest -- standalone Carbon app for Stage A validation.
 *
 * What it does (and ONLY does):
 *   1. Toolbox / Appearance init (Carbon-style, skip the deprecated
 *      InitGraf/InitFonts/etc. inits per CarbonLib convention).
 *   2. Call OSTLS_SmokeTest() once.
 *   3. Open a small window and DrawString the result code.
 *   4. Wait for a mouse click or key press, then quit.
 *
 * What it deliberately does NOT do:
 *   - No Open Transport (smoke test is non-network by design).
 *   - No QuickTime, no Appearance themes beyond default, no menus.
 *   - No file I/O, no preferences, no settings, no resources beyond
 *     the 'carb' Carbon-fragment marker in MacSSLTest.rsrc.
 *
 * Once the smoke test passes on real OS 9 hardware (and the Stage A.5
 * mul64 probe passes too), this file evolves into the seed of
 * MacSSL Proxy: replace the "show dialog + quit" tail with a TCP
 * listener + HTTP proxy parser + BearSSL upstream fetch.
 */

#include "macssltest_prefix.h"

#include <Carbon.h>
#include <stdio.h>
#include <string.h>

#include "ostls_smoketest.h"


/* ------------------------------------------------------------------- */
/* Helpers                                                             */
/* ------------------------------------------------------------------- */

/*
 * Convert a C string to a Pascal string in-place into the supplied
 * buffer. Truncates at 254 chars. CW8 has c2pstr() but it mutates the
 * source buffer; this version is non-destructive and safer.
 */
static void
c_to_pstr(const char *src, Str255 dst)
{
    size_t n = strlen(src);
    if (n > 254) {
        n = 254;
    }
    dst[0] = (unsigned char)n;
    memcpy(&dst[1], src, n);
}


/*
 * Decode an OSTLS smoke-test result code into a human-readable label.
 * Codes correspond to kOSTLSSmoke* in os9/ostls_smoketest.h.
 */
static const char *
smoke_label(OSErr code)
{
    switch ((short)code) {
    case noErr:                         return "OK";
    case kOSTLSSmokeBadEngineAfterReset: return "engine error after reset";
    case kOSTLSSmokeNoSendrecAfterReset: return "engine not asking to send";
    case kOSTLSSmokeClientResetReturned0: return "br_ssl_client_reset = 0";
    case kOSTLSSmokeEntropyInjectFailed: return "entropy inject failed";
    }
    return "unknown failure";
}


/* ------------------------------------------------------------------- */
/* Toolbox init (Carbon discipline)                                    */
/* ------------------------------------------------------------------- */

/*
 * Mirror MacSurf's pattern: skip InitGraf/InitFonts/InitWindows/
 * InitMenus/TEInit/InitDialogs under Carbon, but keep InitCursor() and
 * FlushEvents(). Register the Appearance Manager only if Gestalt
 * confirms it is present.
 */
static void
toolbox_init(void)
{
    InitCursor();
    FlushEvents(everyEvent, 0);

#ifdef __MWERKS__
    /* Gestalt-gated Appearance init. Skipped under Retro68 pre-flight
     * (multiversal headers don't ship Appearance.h); CW8's Carbon.h
     * pulls in everything we need. */
    {
        long response;
        if (Gestalt(gestaltAppearanceAttr, &response) == noErr) {
            RegisterAppearanceClient();
        }
    }
#endif
}


/* ------------------------------------------------------------------- */
/* Result display                                                      */
/* ------------------------------------------------------------------- */

/*
 * Open a single modeless window, draw the result, and pump events
 * until the user clicks or types. No menu bar, no fancy chrome.
 *
 * The window is also given a meaningful title so the user can see the
 * verdict in the title bar before even looking at the content.
 */
static void
show_result_and_wait(OSErr code)
{
    WindowRef win;
    Rect bounds;
    EventRecord ev;
    Boolean done = false;
    Str255 title;
    Str255 line1;
    Str255 line2;
    Str255 line3;
    char buf[128];

    /* Build the four pascal-strings we'll display. */
    if (code == noErr) {
        c_to_pstr("MacSSLTest -- smoke OK", title);
        c_to_pstr("macSSL Stage A smoke: OK", line1);
        c_to_pstr("BearSSL initialised; engine reports SENDREC.", line2);
    } else {
        c_to_pstr("MacSSLTest -- smoke FAILED", title);
        sprintf(buf, "macSSL Stage A smoke: FAILED (code %d)", (int)code);
        c_to_pstr(buf, line1);
        sprintf(buf, "Gate: %s", smoke_label(code));
        c_to_pstr(buf, line2);
    }
    c_to_pstr("Click mouse or press any key to quit.", line3);

    /* Open the window. */
    SetRect(&bounds, 60, 60, 540, 220);
    win = NewCWindow(NULL, &bounds, title, true,
        noGrowDocProc, (WindowRef)-1L, true, 0L);
    if (win == NULL) {
        SysBeep(30);
        return;
    }
    SetPortWindowPort(win);

    /* Pump events until quit. Drawing happens on every updateEvt so
     * the window stays correct if it's covered and uncovered. */
    while (!done) {
        WaitNextEvent(everyEvent, &ev, 30, NULL);
        switch (ev.what) {
        case mouseDown:
        case keyDown:
            done = true;
            break;
        case updateEvt:
            BeginUpdate((WindowRef)ev.message);
            if ((WindowRef)ev.message == win) {
                Rect r;
                GetWindowPortBounds(win, &r);
                EraseRect(&r);

                TextFont(kFontIDGeneva);
                TextSize(12);
                TextFace(bold);
                MoveTo(20, 40);
                DrawString(line1);

                TextFace(0);
                MoveTo(20, 70);
                DrawString(line2);

                TextSize(10);
                MoveTo(20, 130);
                DrawString(line3);
            }
            EndUpdate((WindowRef)ev.message);
            break;
        }
    }

    DisposeWindow(win);
}


/* ------------------------------------------------------------------- */
/* Entry point                                                         */
/* ------------------------------------------------------------------- */

int
main(void)
{
    OSErr smoke;

    toolbox_init();
    smoke = OSTLS_SmokeTest();
    show_result_and_wait(smoke);
    return 0;
}
