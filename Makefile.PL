use ExtUtils::MakeMaker;
require 5.006000;
use strict;

my %opts = (
            'NAME'	   => 'WebService::TicketAuth',
            'VERSION_FROM' => 'lib/WebService/TicketAuth.pm',
	    'EXE_FILES'    => [],
            'PREREQ_PM' => {
                'Digest::MD5'      => 0,
                },
            'AUTHOR'       => 'Bryce Harrington <bryce@osdl.org>',
            'ABSTRACT_FROM'=> 'lib/WebService/TicketAuth.pm',
);

WriteMakefile( %opts );

# vi:set ai ts=4 sw=4 expandtab:
