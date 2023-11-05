# -------------------------------------------------------------------
# File: LDAPtools.pm
# Description: A utility module for LDAP databases
# Author: Bill MacAllister <bill@ca-zephyr.org>
# Copyright (c) 2016-2023 Dropbox, Inc.
# Copyright: 2023 CZ Software

package CZ::LDAPtools;

use Authen::Krb5;
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

    our $VERSION = '5';

}

my $TMP_TGT_FILE;

##############################################################################
# Internal routines
##############################################################################

# ------------------------------------------------------------------------
# Create kerberos ticket cache

sub _create_ticket_cache {
    my $in_ref = shift;
    my %in     = %{$in_ref};

    if ($in{'debug'}) {
        lt_dbg("Creating ticket cache");
    }
    if ($in{'tgt'}) {
        if (-e $in{'tgt'}) {
            my $tgtEnv = 'FILE:' . $in{'tgt'};
            $ENV{KRB5CCNAME} = $tgtEnv;
            if ($in{'debug'}) {
                lt_dbg("Found tgt file, using: " . $tgtEnv);
            }
            return;
        } else {
            die 'ERROR: missing tgt file (' . $in{'tgt'} . ')';
        }
    } else {
        if ($in{'keytab'} && -e $in{'keytab'}) {
            my $princ = $in{'principal'};
            $princ =~ s{/}{_}xmsg;
            $TMP_TGT_FILE = '/tmp/' . $princ . $$ . '.tgt';
            $in{'tgt'} = $TMP_TGT_FILE;
        } else {
            die 'ERROR: Missing keytab (' . $in{'keytab'} . ')';
        }
    }
    if (!$in{'realm'}) {
        die "ERROR parameter 'realm', the Kerberos realm, missing.";
    }
    my $tgtEnv = 'FILE:' . $in{'tgt'};
    $ENV{KRB5CCNAME} = $tgtEnv;

    if ($in{'debug'}) {
        lt_dbg("ticket cache: " . $tgtEnv);
    }

    Authen::Krb5::init_context();
    Authen::Krb5::init_ets();
    if (!$in{'principal'}) {
        die "ERROR parameter 'principal', the Kerberos principal, missing.";
    }
    my $client = Authen::Krb5::parse_name($in{'principal'});
    my $server = Authen::Krb5::parse_name('krbtgt/' . $in{'realm'});
    my $cc     = Authen::Krb5::cc_resolve($tgtEnv);
    $cc->initialize($client);
    my $kt = Authen::Krb5::kt_resolve($in{'keytab'});
    Authen::Krb5::get_in_tkt_with_keytab($client, $server, $kt, $cc)
      or die 'ERROR: '
      . Authen::Krb5::error()
      . " while getting Kerberos ticket";

    return;
}

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
    if ($this_port) {
        $this_port = 389;
    }

    my $ldap;
    if ($in{'debug'}) {
        for my $a (sort keys %in) {
            lt_dbg("in{$a} = $in{$a}");
        }
        lt_dbg("connecting to server " . $this_host);
    }
    if (($ldap = Net::LDAPapi->new($this_host), $this_port) == -1) {
        die "ERROR Connection to " . $this_host . " failed.";
    }
    my $status;
    if ($in{'anonymous'}) {
        if ($in{'debug'}) {
            lt_dbg("anonymous bind to server " . $this_host);
        }
        $status = $ldap->bind_s();
    } else {
        # Create a ticket cache if we need to
        _create_ticket_cache($in_ref);
        if ($in{'debug'}) {
            lt_dbg("GSSAPI bind to server " . $this_host);
        }
        $ldap->sasl_parms(-mech => "GSSAPI");
        $status = $ldap->bind_s(-type => LDAP_AUTH_SASL);
    }
    if ($status != LDAP_SUCCESS) {
        $ldap->unbind if $ldap;
        die 'ERROR Bind error connecting to ' . $this_host;
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

    $DIR = lt_ldap_connect (host      => 'host1,host2,host3',
                            principal => 'service/name',
                            keytab    => '/etc/ldap/ldap-admin.keytab',
                            tgt       => '/run/ldap-server.tgt',
                            anonymous => 'anyvalue',
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

        host - A comma separate list of hostnames of at least one host.
        keytab - if supplied the keytab to use when creating a
            Kerberos ticket cache.  Ignored if tgt is specified.
        principal - the principal name to be used when creating a
            Kerberos ticket cache.  If this value is not specified
            then it is assumed that the KRB5CCNAME environment value
            points to a valid ticket cache.  It set then the tgt
            hash value must also be specified.
        tgt - the file name of the Kerberos ticket cache. If specified the
            file is assumed to have been created by an external process.
            A missing tgt file is an error if no keytab is supplied.
        anonymous - if specified as 'true' then the Kerberos hash
            values are ignore and an anonymous bind is performed.
        debug - display debugging messages to STDOUT

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
