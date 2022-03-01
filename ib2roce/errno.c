/* SPDX-License-Identifier: 0BSD */
/* Copyright 2019 Alexander Kozhevnikov <mentalisttraceur@gmail.com> */

#include <stdio.h>
#include <errno.h>
#include "errno.h"

/* Copied from https://raw.githubusercontent.com/mentalisttraceur/errnoname/master/errnoname.c and modified
 * to be a simple include by cl@linux.com. This should be replaced by strerrorname_np but sadly this is not
 * available in the distro I am using at this point.
 */

char const * errname(void)
{
    static char buf[12];
    static char const * const names[] =
    {
    #ifdef E2BIG
        [E2BIG] = "E2BIG",
    #endif
    #ifdef EACCES
        [EACCES] = "EACCES",
    #endif
    #ifdef EADDRINUSE
        [EADDRINUSE] = "EADDRINUSE",
    #endif
    #ifdef EADDRNOTAVAIL
        [EADDRNOTAVAIL] = "EADDRNOTAVAIL",
    #endif
    #ifdef EADI
        [EADI] = "EADI",
    #endif
    #ifdef EADV
        [EADV] = "EADV",
    #endif
    #ifdef EAFNOSUPPORT
        [EAFNOSUPPORT] = "EAFNOSUPPORT",
    #endif
    #ifdef EAGAIN
        [EAGAIN] = "EAGAIN",
    #endif
    #ifdef EAIO
        [EAIO] = "EAIO",
    #endif
    #ifdef EALIGN
        [EALIGN] = "EALIGN",
    #endif
    #ifdef EALREADY
        [EALREADY] = "EALREADY",
    #endif
    #ifdef EASYNC
        [EASYNC] = "EASYNC",
    #endif
    #ifdef EAUTH
        [EAUTH] = "EAUTH",
    #endif
    #ifdef EBADARCH
        [EBADARCH] = "EBADARCH",
    #endif
    #ifdef EBADCOOKIE
        [EBADCOOKIE] = "EBADCOOKIE",
    #endif
    #ifdef EBADE
        [EBADE] = "EBADE",
    #endif
    #ifdef EBADEXEC
        [EBADEXEC] = "EBADEXEC",
    #endif
    #ifdef EBADF
        [EBADF] = "EBADF",
    #endif
    #ifdef EBADFD
        [EBADFD] = "EBADFD",
    #endif
    #ifdef EBADFSYS
        [EBADFSYS] = "EBADFSYS",
    #endif
    #ifdef EBADHANDLE
        [EBADHANDLE] = "EBADHANDLE",
    #endif
    #ifdef EBADMACHO
        [EBADMACHO] = "EBADMACHO",
    #endif
    #ifdef EBADMSG
        [EBADMSG] = "EBADMSG",
    #endif
    #ifdef EBADOBJ
        [EBADOBJ] = "EBADOBJ",
    #endif
    #ifdef EBADR
        [EBADR] = "EBADR",
    #endif
    #ifdef EBADRPC
        [EBADRPC] = "EBADRPC",
    #endif
    #ifdef EBADRQC
        [EBADRQC] = "EBADRQC",
    #endif
    #ifdef EBADSLT
        [EBADSLT] = "EBADSLT",
    #endif
    #ifdef EBADTYPE
        [EBADTYPE] = "EBADTYPE",
    #endif
    #ifdef EBADVER
        [EBADVER] = "EBADVER",
    #endif
    #ifdef EBFONT
        [EBFONT] = "EBFONT",
    #endif
    #ifdef EBUSY
        [EBUSY] = "EBUSY",
    #endif
    #ifdef ECANCEL
        [ECANCEL] = "ECANCEL",
    #endif
    #ifdef ECANCELED
        [ECANCELED] = "ECANCELED",
    #endif
    #ifdef ECANCELLED
        #if !defined(ECANCELED) || ECANCELLED != ECANCELED
        [ECANCELLED] = "ECANCELLED",
        #endif
    #endif
    #ifdef ECAPMODE
        [ECAPMODE] = "ECAPMODE",
    #endif
    #ifdef ECASECLASH
        [ECASECLASH] = "ECASECLASH",
    #endif
    #ifdef ECHILD
        [ECHILD] = "ECHILD",
    #endif
    #ifdef ECHRNG
        [ECHRNG] = "ECHRNG",
    #endif
    #ifdef ECKPT
        [ECKPT] = "ECKPT",
    #endif
    #ifdef ECKSUM
        [ECKSUM] = "ECKSUM",
    #endif
    #ifdef ECLONEME
        [ECLONEME] = "ECLONEME",
    #endif
    #ifdef ECLOSED
        [ECLOSED] = "ECLOSED",
    #endif
    #ifdef ECOMM
        [ECOMM] = "ECOMM",
    #endif
    #ifdef ECONFIG
        [ECONFIG] = "ECONFIG",
    #endif
    #ifdef ECONNABORTED
        [ECONNABORTED] = "ECONNABORTED",
    #endif
    #ifdef ECONNCLOSED
        [ECONNCLOSED] = "ECONNCLOSED",
    #endif
    #ifdef ECONNREFUSED
        [ECONNREFUSED] = "ECONNREFUSED",
    #endif
    #ifdef ECONNRESET
        [ECONNRESET] = "ECONNRESET",
    #endif
    #ifdef ECONSOLEINTERRUPT
        [ECONSOLEINTERRUPT] = "ECONSOLEINTERRUPT",
    #endif
    #ifdef ECORRUPT
        [ECORRUPT] = "ECORRUPT",
    #endif
    #ifdef ECTRLTERM
        [ECTRLTERM] = "ECTRLTERM",
    #endif
    #ifdef ECVCERORR
        [ECVCERORR] = "ECVCERORR",
    #endif
    #ifdef ECVPERORR
        [ECVPERORR] = "ECVPERORR",
    #endif
    #ifdef EDATALESS
        [EDATALESS] = "EDATALESS",
    #endif
    #ifdef EDEADLK
        [EDEADLK] = "EDEADLK",
    #endif
    #ifdef EDEADLOCK
        #if !defined(EDEADLK) || EDEADLOCK != EDEADLK
        [EDEADLOCK] = "EDEADLOCK",
        #endif
    #endif
    #ifdef EDESTADDREQ
        #if !defined(EDESTADDRREQ) || EDESTADDREQ != EDESTADDRREQ
        [EDESTADDREQ] = "EDESTADDREQ",
        #endif
    #endif
    #ifdef EDESTADDRREQ
        [EDESTADDRREQ] = "EDESTADDRREQ",
    #endif
    #ifdef EDEVERR
        [EDEVERR] = "EDEVERR",
    #endif
    #ifdef EDIRIOCTL
        [EDIRIOCTL] = "EDIRIOCTL",
    #endif
    #ifdef EDIRTY
        [EDIRTY] = "EDIRTY",
    #endif
    #ifdef EDIST
        [EDIST] = "EDIST",
    #endif
    #ifdef EDOM
        [EDOM] = "EDOM",
    #endif
    #ifdef EDOMAINSERVERFAILURE
        [EDOMAINSERVERFAILURE] = "EDOMAINSERVERFAILURE",
    #endif
    #ifdef EDOOFUS
        [EDOOFUS] = "EDOOFUS",
    #endif
    #ifdef EDOTDOT
        [EDOTDOT] = "EDOTDOT",
    #endif
    #ifdef EDQUOT
        [EDQUOT] = "EDQUOT",
    #endif
    #ifdef EDUPFD
        [EDUPFD] = "EDUPFD",
    #endif
    #ifdef EDUPPKG
        [EDUPPKG] = "EDUPPKG",
    #endif
    #ifdef EENDIAN
        [EENDIAN] = "EENDIAN",
    #endif
    #ifdef EEXIST
        [EEXIST] = "EEXIST",
    #endif
    #ifdef EFAIL
        [EFAIL] = "EFAIL",
    #endif
    #ifdef EFAULT
        [EFAULT] = "EFAULT",
    #endif
    #ifdef EFBIG
        [EFBIG] = "EFBIG",
    #endif
    #ifdef EFORMAT
        [EFORMAT] = "EFORMAT",
    #endif
    #ifdef EFPOS
        [EFPOS] = "EFPOS",
    #endif
    #ifdef EFRAGS
        [EFRAGS] = "EFRAGS",
    #endif
    #ifdef EFSCORRUPTED
        [EFSCORRUPTED] = "EFSCORRUPTED",
    #endif
    #ifdef EFTYPE
        [EFTYPE] = "EFTYPE",
    #endif
    #ifdef EHOSTDOWN
        [EHOSTDOWN] = "EHOSTDOWN",
    #endif
    #ifdef EHOSTNOTFOUND
        [EHOSTNOTFOUND] = "EHOSTNOTFOUND",
    #endif
    #ifdef EHOSTUNREACH
        [EHOSTUNREACH] = "EHOSTUNREACH",
    #endif
    #ifdef EHWPOISON
        [EHWPOISON] = "EHWPOISON",
    #endif
    #ifdef EIBMBADCONNECTIONMATCH
        [EIBMBADCONNECTIONMATCH] = "EIBMBADCONNECTIONMATCH",
    #endif
    #ifdef EIBMBADCONNECTIONSTATE
        [EIBMBADCONNECTIONSTATE] = "EIBMBADCONNECTIONSTATE",
    #endif
    #ifdef EIBMBADREQUESTCODE
        [EIBMBADREQUESTCODE] = "EIBMBADREQUESTCODE",
    #endif
    #ifdef EIBMBADTCPNAME
        [EIBMBADTCPNAME] = "EIBMBADTCPNAME",
    #endif
    #ifdef EIBMCALLINPROGRESS
        [EIBMCALLINPROGRESS] = "EIBMCALLINPROGRESS",
    #endif
    #ifdef EIBMCANCELLED
        [EIBMCANCELLED] = "EIBMCANCELLED",
    #endif
    #ifdef EIBMCONFLICT
        [EIBMCONFLICT] = "EIBMCONFLICT",
    #endif
    #ifdef EIBMINVDELETE
        [EIBMINVDELETE] = "EIBMINVDELETE",
    #endif
    #ifdef EIBMINVSOCKET
        [EIBMINVSOCKET] = "EIBMINVSOCKET",
    #endif
    #ifdef EIBMINVTCPCONNECTION
        [EIBMINVTCPCONNECTION] = "EIBMINVTCPCONNECTION",
    #endif
    #ifdef EIBMINVTSRBUSERDATA
        [EIBMINVTSRBUSERDATA] = "EIBMINVTSRBUSERDATA",
    #endif
    #ifdef EIBMINVUSERDATA
        [EIBMINVUSERDATA] = "EIBMINVUSERDATA",
    #endif
    #ifdef EIBMIUCVERR
        [EIBMIUCVERR] = "EIBMIUCVERR",
    #endif
    #ifdef EIBMNOACTIVETCP
        [EIBMNOACTIVETCP] = "EIBMNOACTIVETCP",
    #endif
    #ifdef EIBMSELECTEXPOST
        [EIBMSELECTEXPOST] = "EIBMSELECTEXPOST",
    #endif
    #ifdef EIBMSOCKINUSE
        [EIBMSOCKINUSE] = "EIBMSOCKINUSE",
    #endif
    #ifdef EIBMSOCKOUTOFRANGE
        [EIBMSOCKOUTOFRANGE] = "EIBMSOCKOUTOFRANGE",
    #endif
    #ifdef EIBMTCPABEND
        [EIBMTCPABEND] = "EIBMTCPABEND",
    #endif
    #ifdef EIBMTERMERROR
        [EIBMTERMERROR] = "EIBMTERMERROR",
    #endif
    #ifdef EIBMUNAUTHORIZEDCALLER
        [EIBMUNAUTHORIZEDCALLER] = "EIBMUNAUTHORIZEDCALLER",
    #endif
    #ifdef EIDRM
        [EIDRM] = "EIDRM",
    #endif
    #ifdef EILSEQ
        [EILSEQ] = "EILSEQ",
    #endif
    #ifdef EINIT
        [EINIT] = "EINIT",
    #endif
    #ifdef EINPROG
        #if !defined(EINPROGRESS) || EINPROG != EINPROGRESS
        [EINPROG] = "EINPROG",
        #endif
    #endif
    #ifdef EINPROGRESS
        [EINPROGRESS] = "EINPROGRESS",
    #endif
    #ifdef EINTEGRITY
        [EINTEGRITY] = "EINTEGRITY",
    #endif
    #ifdef EINTR
        [EINTR] = "EINTR",
    #endif
    #ifdef EINTRNODATA
        [EINTRNODATA] = "EINTRNODATA",
    #endif
    #ifdef EINVAL
        [EINVAL] = "EINVAL",
    #endif
    #ifdef EINVALIDCLIENTID
        [EINVALIDCLIENTID] = "EINVALIDCLIENTID",
    #endif
    #ifdef EINVALIDCOMBINATION
        [EINVALIDCOMBINATION] = "EINVALIDCOMBINATION",
    #endif
    #ifdef EINVALIDNAME
        [EINVALIDNAME] = "EINVALIDNAME",
    #endif
    #ifdef EINVALIDRXSOCKETCALL
        [EINVALIDRXSOCKETCALL] = "EINVALIDRXSOCKETCALL",
    #endif
    #ifdef EIO
        [EIO] = "EIO",
    #endif
    #ifdef EIOCBQUEUED
        [EIOCBQUEUED] = "EIOCBQUEUED",
    #endif
    #ifdef EIPADDRNOTFOUND
        [EIPADDRNOTFOUND] = "EIPADDRNOTFOUND",
    #endif
    #ifdef EIPSEC
        [EIPSEC] = "EIPSEC",
    #endif
    #ifdef EISCONN
        [EISCONN] = "EISCONN",
    #endif
    #ifdef EISDIR
        [EISDIR] = "EISDIR",
    #endif
    #ifdef EISNAM
        [EISNAM] = "EISNAM",
    #endif
    #ifdef EJUKEBOX
        [EJUKEBOX] = "EJUKEBOX",
    #endif
    #ifdef EJUSTRETURN
        [EJUSTRETURN] = "EJUSTRETURN",
    #endif
    #ifdef EKEEPLOOKING
        [EKEEPLOOKING] = "EKEEPLOOKING",
    #endif
    #ifdef EKEYEXPIRED
        [EKEYEXPIRED] = "EKEYEXPIRED",
    #endif
    #ifdef EKEYREJECTED
        [EKEYREJECTED] = "EKEYREJECTED",
    #endif
    #ifdef EKEYREVOKED
        [EKEYREVOKED] = "EKEYREVOKED",
    #endif
    #ifdef EL2HLT
        [EL2HLT] = "EL2HLT",
    #endif
    #ifdef EL2NSYNC
        [EL2NSYNC] = "EL2NSYNC",
    #endif
    #ifdef EL3HLT
        [EL3HLT] = "EL3HLT",
    #endif
    #ifdef EL3RST
        [EL3RST] = "EL3RST",
    #endif
    #ifdef ELBIN
        [ELBIN] = "ELBIN",
    #endif
    #ifdef ELIBACC
        [ELIBACC] = "ELIBACC",
    #endif
    #ifdef ELIBBAD
        [ELIBBAD] = "ELIBBAD",
    #endif
    #ifdef ELIBEXEC
        [ELIBEXEC] = "ELIBEXEC",
    #endif
    #ifdef ELIBMAX
        [ELIBMAX] = "ELIBMAX",
    #endif
    #ifdef ELIBSCN
        [ELIBSCN] = "ELIBSCN",
    #endif
    #ifdef ELINKED
        [ELINKED] = "ELINKED",
    #endif
    #ifdef ELNRNG
        [ELNRNG] = "ELNRNG",
    #endif
    #ifdef ELOCKUNMAPPED
        [ELOCKUNMAPPED] = "ELOCKUNMAPPED",
    #endif
    #ifdef ELOOP
        [ELOOP] = "ELOOP",
    #endif
    #ifdef EMAXSOCKETSREACHED
        [EMAXSOCKETSREACHED] = "EMAXSOCKETSREACHED",
    #endif
    #ifdef EMEDIA
        [EMEDIA] = "EMEDIA",
    #endif
    #ifdef EMEDIUMTYPE
        [EMEDIUMTYPE] = "EMEDIUMTYPE",
    #endif
    #ifdef EMFILE
        [EMFILE] = "EMFILE",
    #endif
    #ifdef EMISSED
        [EMISSED] = "EMISSED",
    #endif
    #ifdef EMLINK
        [EMLINK] = "EMLINK",
    #endif
    #ifdef EMORE
        [EMORE] = "EMORE",
    #endif
    #ifdef EMOUNTEXIT
        [EMOUNTEXIT] = "EMOUNTEXIT",
    #endif
    #ifdef EMOVEFD
        [EMOVEFD] = "EMOVEFD",
    #endif
    #ifdef EMSGSIZE
        [EMSGSIZE] = "EMSGSIZE",
    #endif
    #ifdef EMTIMERS
        [EMTIMERS] = "EMTIMERS",
    #endif
    #ifdef EMULTIHOP
        [EMULTIHOP] = "EMULTIHOP",
    #endif
    #ifdef EMVSARMERROR
        [EMVSARMERROR] = "EMVSARMERROR",
    #endif
    #ifdef EMVSCATLG
        [EMVSCATLG] = "EMVSCATLG",
    #endif
    #ifdef EMVSCPLERROR
        [EMVSCPLERROR] = "EMVSCPLERROR",
    #endif
    #ifdef EMVSCVAF
        [EMVSCVAF] = "EMVSCVAF",
    #endif
    #ifdef EMVSDYNALC
        [EMVSDYNALC] = "EMVSDYNALC",
    #endif
    #ifdef EMVSERR
        [EMVSERR] = "EMVSERR",
    #endif
    #ifdef EMVSEXPIRE
        [EMVSEXPIRE] = "EMVSEXPIRE",
    #endif
    #ifdef EMVSINITIAL
        [EMVSINITIAL] = "EMVSINITIAL",
    #endif
    #ifdef EMVSNORTL
        [EMVSNORTL] = "EMVSNORTL",
    #endif
    #ifdef EMVSNOTUP
        [EMVSNOTUP] = "EMVSNOTUP",
    #endif
    #ifdef EMVSPARM
        [EMVSPARM] = "EMVSPARM",
    #endif
    #ifdef EMVSPASSWORD
        [EMVSPASSWORD] = "EMVSPASSWORD",
    #endif
    #ifdef EMVSPFSFILE
        [EMVSPFSFILE] = "EMVSPFSFILE",
    #endif
    #ifdef EMVSPFSPERM
        [EMVSPFSPERM] = "EMVSPFSPERM",
    #endif
    #ifdef EMVSSAF2ERR
        [EMVSSAF2ERR] = "EMVSSAF2ERR",
    #endif
    #ifdef EMVSSAFEXTRERR
        [EMVSSAFEXTRERR] = "EMVSSAFEXTRERR",
    #endif
    #ifdef EMVSWLMERROR
        [EMVSWLMERROR] = "EMVSWLMERROR",
    #endif
    #ifdef ENAMETOOLONG
        [ENAMETOOLONG] = "ENAMETOOLONG",
    #endif
    #ifdef ENAVAIL
        [ENAVAIL] = "ENAVAIL",
    #endif
    #ifdef ENEEDAUTH
        [ENEEDAUTH] = "ENEEDAUTH",
    #endif
    #ifdef ENETDOWN
        [ENETDOWN] = "ENETDOWN",
    #endif
    #ifdef ENETRESET
        [ENETRESET] = "ENETRESET",
    #endif
    #ifdef ENETUNREACH
        [ENETUNREACH] = "ENETUNREACH",
    #endif
    #ifdef ENFILE
        [ENFILE] = "ENFILE",
    #endif
    #ifdef ENFSREMOTE
        [ENFSREMOTE] = "ENFSREMOTE",
    #endif
    #ifdef ENIVALIDFILENAME
        [ENIVALIDFILENAME] = "ENIVALIDFILENAME",
    #endif
    #ifdef ENMELONG
        [ENMELONG] = "ENMELONG",
    #endif
    #ifdef ENMFILE
        [ENMFILE] = "ENMFILE",
    #endif
    #ifdef ENOANO
        [ENOANO] = "ENOANO",
    #endif
    #ifdef ENOATTR
        [ENOATTR] = "ENOATTR",
    #endif
    #ifdef ENOBUFS
        [ENOBUFS] = "ENOBUFS",
    #endif
    #ifdef ENOCONNECT
        [ENOCONNECT] = "ENOCONNECT",
    #endif
    #ifdef ENOCSI
        [ENOCSI] = "ENOCSI",
    #endif
    #ifdef ENODATA
        [ENODATA] = "ENODATA",
    #endif
    #ifdef ENODEV
        [ENODEV] = "ENODEV",
    #endif
    #ifdef ENOENT
        [ENOENT] = "ENOENT",
    #endif
    #ifdef ENOEXEC
        [ENOEXEC] = "ENOEXEC",
    #endif
    #ifdef ENOGRACE
        [ENOGRACE] = "ENOGRACE",
    #endif
    #ifdef ENOIOCTL
        [ENOIOCTL] = "ENOIOCTL",
    #endif
    #ifdef ENOIOCTLCMD
        [ENOIOCTLCMD] = "ENOIOCTLCMD",
    #endif
    #ifdef ENOKEY
        [ENOKEY] = "ENOKEY",
    #endif
    #ifdef ENOLCK
        [ENOLCK] = "ENOLCK",
    #endif
    #ifdef ENOLIC
        [ENOLIC] = "ENOLIC",
    #endif
    #ifdef ENOLINK
        [ENOLINK] = "ENOLINK",
    #endif
    #ifdef ENOLOAD
        [ENOLOAD] = "ENOLOAD",
    #endif
    #ifdef ENOMATCH
        [ENOMATCH] = "ENOMATCH",
    #endif
    #ifdef ENOMEDIUM
        [ENOMEDIUM] = "ENOMEDIUM",
    #endif
    #ifdef ENOMEM
        [ENOMEM] = "ENOMEM",
    #endif
    #ifdef ENOMOVE
        [ENOMOVE] = "ENOMOVE",
    #endif
    #ifdef ENOMSG
        [ENOMSG] = "ENOMSG",
    #endif
    #ifdef ENONDP
        [ENONDP] = "ENONDP",
    #endif
    #ifdef ENONET
        [ENONET] = "ENONET",
    #endif
    #ifdef ENOPARAM
        [ENOPARAM] = "ENOPARAM",
    #endif
    #ifdef ENOPARTNERINFO
        [ENOPARTNERINFO] = "ENOPARTNERINFO",
    #endif
    #ifdef ENOPKG
        [ENOPKG] = "ENOPKG",
    #endif
    #ifdef ENOPOLICY
        [ENOPOLICY] = "ENOPOLICY",
    #endif
    #ifdef ENOPROTOOPT
        [ENOPROTOOPT] = "ENOPROTOOPT",
    #endif
    #ifdef ENOREG
        [ENOREG] = "ENOREG",
    #endif
    #ifdef ENOREMOTE
        [ENOREMOTE] = "ENOREMOTE",
    #endif
    #ifdef ENOREUSE
        [ENOREUSE] = "ENOREUSE",
    #endif
    #ifdef ENOSHARE
        [ENOSHARE] = "ENOSHARE",
    #endif
    #ifdef ENOSPC
        [ENOSPC] = "ENOSPC",
    #endif
    #ifdef ENOSR
        [ENOSR] = "ENOSR",
    #endif
    #ifdef ENOSTR
        [ENOSTR] = "ENOSTR",
    #endif
    #ifdef ENOSYM
        [ENOSYM] = "ENOSYM",
    #endif
    #ifdef ENOSYS
        [ENOSYS] = "ENOSYS",
    #endif
    #ifdef ENOTACTIVE
        [ENOTACTIVE] = "ENOTACTIVE",
    #endif
    #ifdef ENOTBLK
        [ENOTBLK] = "ENOTBLK",
    #endif
    #ifdef ENOTCAPABLE
        [ENOTCAPABLE] = "ENOTCAPABLE",
    #endif
    #ifdef ENOTCONN
        [ENOTCONN] = "ENOTCONN",
    #endif
    #ifdef ENOTDIR
        [ENOTDIR] = "ENOTDIR",
    #endif
    #ifdef ENOTEMPT
        [ENOTEMPT] = "ENOTEMPT",
    #endif
    #ifdef ENOTEMPTY
        [ENOTEMPTY] = "ENOTEMPTY",
    #endif
    #ifdef ENOTNAM
        [ENOTNAM] = "ENOTNAM",
    #endif
    #ifdef ENOTREADY
        [ENOTREADY] = "ENOTREADY",
    #endif
    #ifdef ENOTRECOVERABLE
        [ENOTRECOVERABLE] = "ENOTRECOVERABLE",
    #endif
    #ifdef ENOTRUST
        [ENOTRUST] = "ENOTRUST",
    #endif
    #ifdef ENOTSOCK
        [ENOTSOCK] = "ENOTSOCK",
    #endif
    #ifdef ENOTSUP
        [ENOTSUP] = "ENOTSUP",
    #endif
    #ifdef ENOTSUPP
        [ENOTSUPP] = "ENOTSUPP",
    #endif
    #ifdef ENOTSYNC
        [ENOTSYNC] = "ENOTSYNC",
    #endif
    #ifdef ENOTTY
        [ENOTTY] = "ENOTTY",
    #endif
    #ifdef ENOTUNIQ
        [ENOTUNIQ] = "ENOTUNIQ",
    #endif
    #ifdef ENOUNLD
        [ENOUNLD] = "ENOUNLD",
    #endif
    #ifdef ENOUNREG
        [ENOUNREG] = "ENOUNREG",
    #endif
    #ifdef ENXIO
        [ENXIO] = "ENXIO",
    #endif
    #ifdef EOFFLOADboxDOWN
        [EOFFLOADboxDOWN] = "EOFFLOADboxDOWN",
    #endif
    #ifdef EOFFLOADboxERROR
        [EOFFLOADboxERROR] = "EOFFLOADboxERROR",
    #endif
    #ifdef EOFFLOADboxRESTART
        [EOFFLOADboxRESTART] = "EOFFLOADboxRESTART",
    #endif
    #ifdef EOPCOMPLETE
        [EOPCOMPLETE] = "EOPCOMPLETE",
    #endif
    #ifdef EOPENSTALE
        [EOPENSTALE] = "EOPENSTALE",
    #endif
    #ifdef EOPNOTSUPP
        #if !defined(ENOTSUP) || EOPNOTSUPP != ENOTSUP
        [EOPNOTSUPP] = "EOPNOTSUPP",
        #endif
    #endif
    #ifdef EOUTOFSTATE
        [EOUTOFSTATE] = "EOUTOFSTATE",
    #endif
    #ifdef EOVERFLOW
        [EOVERFLOW] = "EOVERFLOW",
    #endif
    #ifdef EOWNERDEAD
        [EOWNERDEAD] = "EOWNERDEAD",
    #endif
    #ifdef EPASSTHROUGH
        [EPASSTHROUGH] = "EPASSTHROUGH",
    #endif
    #ifdef EPATHREMOTE
        [EPATHREMOTE] = "EPATHREMOTE",
    #endif
    #ifdef EPERM
        [EPERM] = "EPERM",
    #endif
    #ifdef EPFNOSUPPORT
        [EPFNOSUPPORT] = "EPFNOSUPPORT",
    #endif
    #ifdef EPIPE
        [EPIPE] = "EPIPE",
    #endif
    #ifdef EPOWERF
        [EPOWERF] = "EPOWERF",
    #endif
    #ifdef EPROBE_DEFER
        [EPROBE_DEFER] = "EPROBE_DEFER",
    #endif
    #ifdef EPROCLIM
        [EPROCLIM] = "EPROCLIM",
    #endif
    #ifdef EPROCUNAVAIL
        [EPROCUNAVAIL] = "EPROCUNAVAIL",
    #endif
    #ifdef EPROGMISMATCH
        [EPROGMISMATCH] = "EPROGMISMATCH",
    #endif
    #ifdef EPROGUNAVAIL
        [EPROGUNAVAIL] = "EPROGUNAVAIL",
    #endif
    #ifdef EPROTO
        [EPROTO] = "EPROTO",
    #endif
    #ifdef EPROTONOSUPPORT
        [EPROTONOSUPPORT] = "EPROTONOSUPPORT",
    #endif
    #ifdef EPROTOTYPE
        [EPROTOTYPE] = "EPROTOTYPE",
    #endif
    #ifdef EPWROFF
        [EPWROFF] = "EPWROFF",
    #endif
    #ifdef EQFULL
        [EQFULL] = "EQFULL",
    #endif
    #ifdef EQSUSPENDED
        [EQSUSPENDED] = "EQSUSPENDED",
    #endif
    #ifdef ERANGE
        [ERANGE] = "ERANGE",
    #endif
    #ifdef ERECALLCONFLICT
        [ERECALLCONFLICT] = "ERECALLCONFLICT",
    #endif
    #ifdef ERECURSE
        [ERECURSE] = "ERECURSE",
    #endif
    #ifdef ERECYCLE
        [ERECYCLE] = "ERECYCLE",
    #endif
    #ifdef EREDRIVEOPEN
        [EREDRIVEOPEN] = "EREDRIVEOPEN",
    #endif
    #ifdef EREFUSED
        #if !defined(ECONNREFUSED) || EREFUSED != ECONNREFUSED
        [EREFUSED] = "EREFUSED",
        #endif
    #endif
    #ifdef ERELOC
        [ERELOC] = "ERELOC",
    #endif
    #ifdef ERELOCATED
        [ERELOCATED] = "ERELOCATED",
    #endif
    #ifdef ERELOOKUP
        [ERELOOKUP] = "ERELOOKUP",
    #endif
    #ifdef EREMCHG
        [EREMCHG] = "EREMCHG",
    #endif
    #ifdef EREMDEV
        [EREMDEV] = "EREMDEV",
    #endif
    #ifdef EREMOTE
        [EREMOTE] = "EREMOTE",
    #endif
    #ifdef EREMOTEIO
        [EREMOTEIO] = "EREMOTEIO",
    #endif
    #ifdef EREMOTERELEASE
        [EREMOTERELEASE] = "EREMOTERELEASE",
    #endif
    #ifdef ERESTART
        [ERESTART] = "ERESTART",
    #endif
    #ifdef ERESTARTNOHAND
        [ERESTARTNOHAND] = "ERESTARTNOHAND",
    #endif
    #ifdef ERESTARTNOINTR
        [ERESTARTNOINTR] = "ERESTARTNOINTR",
    #endif
    #ifdef ERESTARTSYS
        [ERESTARTSYS] = "ERESTARTSYS",
    #endif
    #ifdef ERESTART_RESTARTBLOCK
        [ERESTART_RESTARTBLOCK] = "ERESTART_RESTARTBLOCK",
    #endif
    #ifdef ERFKILL
        [ERFKILL] = "ERFKILL",
    #endif
    #ifdef EROFS
        [EROFS] = "EROFS",
    #endif
    #ifdef ERPCMISMATCH
        [ERPCMISMATCH] = "ERPCMISMATCH",
    #endif
    #ifdef ERREMOTE
        [ERREMOTE] = "ERREMOTE",
    #endif
    #ifdef ESAD
        [ESAD] = "ESAD",
    #endif
    #ifdef ESECTYPEINVAL
        [ESECTYPEINVAL] = "ESECTYPEINVAL",
    #endif
    #ifdef ESERVERFAULT
        [ESERVERFAULT] = "ESERVERFAULT",
    #endif
    #ifdef ESHLIBVERS
        [ESHLIBVERS] = "ESHLIBVERS",
    #endif
    #ifdef ESHUTDOWN
        [ESHUTDOWN] = "ESHUTDOWN",
    #endif
    #ifdef ESIGPARM
        [ESIGPARM] = "ESIGPARM",
    #endif
    #ifdef ESOCKETNOTALLOCATED
        [ESOCKETNOTALLOCATED] = "ESOCKETNOTALLOCATED",
    #endif
    #ifdef ESOCKETNOTDEFINED
        [ESOCKETNOTDEFINED] = "ESOCKETNOTDEFINED",
    #endif
    #ifdef ESOCKTNOSUPPORT
        [ESOCKTNOSUPPORT] = "ESOCKTNOSUPPORT",
    #endif
    #ifdef ESOFT
        [ESOFT] = "ESOFT",
    #endif
    #ifdef ESPIPE
        [ESPIPE] = "ESPIPE",
    #endif
    #ifdef ESRCH
        [ESRCH] = "ESRCH",
    #endif
    #ifdef ESRMNT
        [ESRMNT] = "ESRMNT",
    #endif
    #ifdef ESRVRFAULT
        [ESRVRFAULT] = "ESRVRFAULT",
    #endif
    #ifdef ESTALE
        [ESTALE] = "ESTALE",
    #endif
    #ifdef ESTRPIPE
        [ESTRPIPE] = "ESTRPIPE",
    #endif
    #ifdef ESUBTASKALREADYACTIVE
        [ESUBTASKALREADYACTIVE] = "ESUBTASKALREADYACTIVE",
    #endif
    #ifdef ESUBTASKINVALID
        [ESUBTASKINVALID] = "ESUBTASKINVALID",
    #endif
    #ifdef ESUBTASKNOTACTIVE
        [ESUBTASKNOTACTIVE] = "ESUBTASKNOTACTIVE",
    #endif
    #ifdef ESYSERROR
        [ESYSERROR] = "ESYSERROR",
    #endif
    #ifdef ETERM
        [ETERM] = "ETERM",
    #endif
    #ifdef ETIME
        [ETIME] = "ETIME",
    #endif
    #ifdef ETIMEDOUT
        [ETIMEDOUT] = "ETIMEDOUT",
    #endif
    #ifdef ETOOMANYREFS
        [ETOOMANYREFS] = "ETOOMANYREFS",
    #endif
    #ifdef ETOOSMALL
        [ETOOSMALL] = "ETOOSMALL",
    #endif
    #ifdef ETXTBSY
        [ETXTBSY] = "ETXTBSY",
    #endif
    #ifdef ETcpBadObj
        [ETcpBadObj] = "ETcpBadObj",
    #endif
    #ifdef ETcpClosed
        [ETcpClosed] = "ETcpClosed",
    #endif
    #ifdef ETcpErr
        [ETcpErr] = "ETcpErr",
    #endif
    #ifdef ETcpLinked
        [ETcpLinked] = "ETcpLinked",
    #endif
    #ifdef ETcpOutOfState
        [ETcpOutOfState] = "ETcpOutOfState",
    #endif
    #ifdef ETcpUnattach
        [ETcpUnattach] = "ETcpUnattach",
    #endif
    #ifdef EUCLEAN
        [EUCLEAN] = "EUCLEAN",
    #endif
    #ifdef EUNATCH
        [EUNATCH] = "EUNATCH",
    #endif
    #ifdef EUNKNOWN
        [EUNKNOWN] = "EUNKNOWN",
    #endif
    #ifdef EUSERS
        [EUSERS] = "EUSERS",
    #endif
    #ifdef EVERSION
        [EVERSION] = "EVERSION",
    #endif
    #ifdef EWOULDBLOCK
        #if !defined(EAGAIN) || EWOULDBLOCK != EAGAIN
        [EWOULDBLOCK] = "EWOULDBLOCK",
        #endif
    #endif
    #ifdef EWRONGFS
        [EWRONGFS] = "EWRONGFS",
    #endif
    #ifdef EWRPROTECT
        [EWRPROTECT] = "EWRPROTECT",
    #endif
    #ifdef EXDEV
        [EXDEV] = "EXDEV",
    #endif
    #ifdef EXFULL
        [EXFULL] = "EXFULL",
    #endif
    };

	if(errno >= 0 && errno < (sizeof(names) / sizeof(*names)) && names[errno])
		return names[errno];

	snprintf(buf, sizeof(buf), "%d", errno);
	return buf;
}
