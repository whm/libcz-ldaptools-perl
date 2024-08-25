# -------------------------------------------------------------------
# File: LDAPtools.pm
# Description: A utility module for LDAP databases
# Author: Bill MacAllister <bill@ca-zephyr.org>
# Copyright (c) 2016-2023 Dropbox, Inc.
# Copyright: 2023 CZ Software

package CZ::LDAPtools;

use Net::LDAPapi;
use strict;

BEGIN {

    use Exporter();

    our @ISA    = qw(Exporter);
    our @EXPORT = qw(
      lt_dbg
      lt_format_acls
      lt_ldap_connect
      lt_ldap_disconnect
      lt_msg
      lt_pool_host
    );

    our $VERSION = '6';

}

my $TMP_TGT_FILE;

##############################################################################
# Public Routines
##############################################################################

# ------------------------------------------------------------------------
# Debugging display

sub lt_dbg {
    my ($msg) = @_;
    print("DEBUG: $msg\n") or die "Error writing to STDOUT\n";
    return;
}

# ------------------------------------------------------------------------
# Print a line of text

sub lt_msg {
    my ($msg) = @_;
    print("$msg\n") or die "Error writing to STDOUT\n";
    return;
}

# --------------------------------------------------------------------
# Return the ACL in a human readable format

sub lt_format_acls {
    my ($in) = @_;
    my $out = "$in";

    # Remove extra whitespace
    $out =~ s{\s\s+(attrs=)}{ $1}xms;
    $out =~ s{\s\s+(by\s+)}{ $1}xmsg;

    # Add the whitespace and some new lines to make the
    # ACL more readable.
    $out =~ s{\s+(attrs=)}{\n  $1}xms;
    $out =~ s{\s+(by\s+)}{\n    $1}xmsg;

    return $out;
}

# ------------------------------------------------------------------------
# Bind to the directory for reading

sub lt_ldap_connect {
    my $in_ref = shift;
    my %in     = %{$in_ref};

    my $this_host = $in{'host'};
    if (!$this_host) {
        $this_host = 'localhost';
    }
    my $this_port = $in{'port'};
    if (!$this_port) {
        $this_port = 389;
    }

    my $ldap;
    if ($in{'debug'}) {
        for my $a (sort keys %in) {
            lt_dbg("in{$a} = $in{$a}");
        }
        lt_dbg("connecting to server $this_host:$this_port");
    }
    if (($ldap = Net::LDAPapi->new($this_host, $this_port)) == -1) {
        die "ERROR Connection to $this_host:$this_port failed.";
    }
    my $status;
    if ($in{'bindtype'} eq 'anonymous') {
        if ($in{'debug'}) {
            lt_dbg("anonymous bind to server $this_host:$this_port");
        }
        if ($ldap->bind_s() != LDAP_SUCCESS) {
            my $errstr = $ldap->errstring;
            $ldap->unbind;
            die("ERROR anonymous bind: ", $errstr);
        }
    } elsif ($in{'bindtype'} eq 'simple') {
        if (!$in{'user_dn'}) {
            die('missing parameter user_dn');
        }
        if (!$in{'user_pw'}) {
            die('missing parameter user_pw');
        }
        if ($in{'debug'}) {
            lt_dbg("simple bind to server $this_host:$this_port");
        }
        if ($ldap->bind_s($in{'user_dn'}, $in{'user_pw'}) != LDAP_SUCCESS) {
            my $errstr = $ldap->errstring;
            die("ERROR anonymous bind: ", $errstr);
        }
    } elsif ($in{'bindtype'} eq 'gssapi') {
        if ($in{'debug'}) {
            lt_dbg("GSSAPI bind to server  $this_host:$this_port");
        }
        if (($ldap->sasl_parms(-mech => "GSSAPI")) != LDAP_SUCCESS) {
            if ($in{'debug'}) {
                lt_dbg('sasl_parms: ' . $ldap->errstring);
            }
        }
        if ($ldap->bind_s(-type => LDAP_AUTH_SASL) != LDAP_SUCCESS) {
            if ($in{'debug'}) {
                lt_dbg('GSSAPI bind: ' . $ldap->errstring);
            }
        }
    } else {
        die("ERROR Invalid bindtype: ", $in{'bindtype'});
    }
    return $ldap;
}

# ------------------------------------------------------------------------
# Close the read connection to the ldap server

sub lt_ldap_disconnect {
    my ($ldap) = @_;
    if ($TMP_TGT_FILE && -e $TMP_TGT_FILE) {
        unlink $TMP_TGT_FILE;
    }
    $ldap->unbind if $ldap;
    return;
}

# ------------------------------------------------------------------------
# Select a host from a list of hosts

sub lt_pool_host {
    my ($host) = @_;
    my @host_list = ();
    @host_list = split(/,/, $host);
    my $idx       = int(rand() * scalar(@host_list));
    my $pool_host = $host_list[$idx];
    $pool_host =~ s/\s+//xmsg;
    return $pool_host;
}

END { }

1;

=head1 NAME

CZ::LDAPtools - Utility routines for the LDAP Servers

=head1 SYNOPSIS

    use CZ::LDAPtools;

    $DIR = lt_ldap_connect(host      => 'host1,host2,host3',
                           bindtype  => 'anonymous'|'simple'|'gssapi',
                           user_dn   => 'some dn',
                           user_pw   => 'some password',
                           debug     => 'anyvalue');

    lt_ldap_disconnect ($DIR);

    lt_dbg('some message');

    lt_msg('some text');

    my $acl = lt_format_acls($<acl string>);

    $ldap_hostname = lt_pool_host('host1,host2,host3');

=head1 DESCRIPTION

This module holds common routines used by perl scripts when accessing
LDAP servers.

=head1 FUNCTIONS

=over 4

=item lt_dbg

Displays the message passed as parameter with the prefix 'DEBUG:'.

=item lt_format_acls

Format ACL entry for display to human beings.  The single input is
the ACL to be formated.  The ACL is returned with added white space
to make the ACL more readable.

=item lt_ldap_connect

Connect to an LDAP directory.  An LDAP directory connection object is
returned.  Parameters are passed to the routine as hash key value
pairs.  Valid hash entries are;

        host - A comma separate list of hostnames.
        port - The port to bind to.
        bindtype - The bind method when connecting to the LDAP
            server.  Values of anonymous, simple, and gssapi are
            supported.
        debug - Display debugging messages to STDOUT

=item lt_pool_host('host1,host2,host3')

Randomly select a host from a list of hosts.  If no host list is
specifed then the host list specified in the configuration file is
used.

=item lt_ldap_disconnect($DIR)

Disconnects from the directory server.  The directory object paramter
is required.

=item lt_msg

Prints a line of text to STDOUT.

=back

=head1 AUTHOR

Bill MacAllister <bill@ca-zephyr.org>

=head1 COPYRIGHT

Copyright (C) 2016-2023, Dropbox Inc.

This code is free software; you can redistribute it and/or modify it
under the same terms as Perl. For more details, see the full
text of the at https://opensource.org/licenses/Artistic-2.0.

This program is distributed in the hope that it will be
useful, but without any warranty; without even the implied
warranty of merchantability or fitness for a particular purpose.

Copyright 2023 CZ Software

Permission is hereby granted, free of charge, to any person obtaining
a copy of this software and associated documentation files (the
"Software"), to deal in the Software without restriction, including
without limitation the rights to use, copy, modify, merge, publish,
distribute, sublicense, and/or sell copies of the Software, and to
permit persons to whom the Software is furnished to do so, subject to
the following conditions:

The above copyright notice and this permission notice shall be
included in all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.
IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY
CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT,
TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE
SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.

=cut
