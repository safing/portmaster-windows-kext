#define STRINGIZE2(s) #s
#define STRINGIZE(s) STRINGIZE2(s)

#define PM_VERSION            PM_VERSION_MAJOR, PM_VERSION_MINOR, PM_VERSION_REVISION, PM_VERSION_BUILD
#define PM_VERSION_STR        STRINGIZE(PM_VERSION_MAJOR)        \
                                "." STRINGIZE(PM_VERSION_MINOR)    \
                                "." STRINGIZE(PM_VERSION_REVISION) \
                                "." STRINGIZE(PM_VERSION_BUILD)


#define COMPANY_NAME "Safing ICS Technologies GmbH"
#define LEGAL_COPYWRITE "Safing ICS Technologies GmbH"
