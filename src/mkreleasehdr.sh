#!/bin/bash
#SVN_REV=`svnversion -n .`
#SVN_DIRTY=`svn diff 2>/dev/null | wc -l`
#BUILD_ID=`uname -n`"-"`date +%s`
BUILD_TIME=`date +'%F %T'`

test -f ../inc/zrouter_version.h || touch ../inc/zrouter_version.h

#(cat ../inc/sdpd_version.h | grep SVN_REV | grep $SVN_REV) && \
#[[ `cat ../inc/sdpd_version.h | grep SVN_REV | awk '{printf $3}' | tr -d '"'` == "$SVN_REV" ]] && \
#(cat ../inc/sdpd_version.h | grep SVN_DIRTY | grep $SVN_DIRTY) && exit 0 # Already up-to-date

#echo "#define SDPD_SVN_REV  \"$SVN_REV\"" > ../inc/sdpd_version.h
#echo "#define SDPD_SVN_DIRTY \"$SVN_DIRTY\"" >> ../inc/sdpd_version.h
echo "#define ZROUTER_BUILD_TIME \"$BUILD_TIME\"" >> ../inc/zrouter_version.h

#touch src/sdpd_version.c # Force recompile of sdpd_version.c
