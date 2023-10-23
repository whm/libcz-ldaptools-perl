# -------------------------------------------------------------------
# File: LDAPtools.pm
# Description: This module is used by the an assortment of LDAP server tools
# Author: Bill MacAllister <bill@ca-zephyr.org>
# Copyright (c) 2016-2023 Dropbox, Inc.
# Copyright: 2023 CZ Software

package CZ::LDAPtools;

use AppConfig qw(:argcount :expand);
use Authen::Krb5;
use IPC::Run;
use Net::LDAPapi;
use strict;

BEGIN {

    use Exporter();

    our @ISA    = qw(Exporter);
    our @EXPORT = qw(
      lt_dbg
      lt_example_conf
      lt_format_acls
      lt_ldap_connect
      lt_ldap_disconnect
      lt_msg
      lt_pool_host
      lt_read_conf
      lt_run_cmd
      format_acls
      ldap_connect
      ldap_disconnect
      read_ldaptools_conf
    );

    our $VERSION = '4';

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
# Backwards compatibility routines
##############################################################################

# ------------------------------------------------------------------------
# Read configuration properties

sub read_ldaptools_conf {
    return lt_read_conf(@_);
}

# --------------------------------------------------------------------
# Return the ACL in a human readable format

sub format_acls {
    return lt_format_acls(@_);
}

# ------------------------------------------------------------------------
# Bind to the directory for reading

sub ldap_connect {
    return lt_ldap_connect(@_);
}

# ------------------------------------------------------------------------
# Close the read connection to the ldap server

sub ldap_disconnect {
    return lt_ldap_disconnect(@_);
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

#------------------------------------------------------------------------
# Print example configuratino file

sub lt_example_conf {

    lt_msg('# /etc/ldaptools.conf');
    lt_msg('default_domain   = ca-zephyr.org');
    lt_msg('dump_config      = /var/tmp/cn-config.ldif');
    lt_msg('dump_db          = /var/tmp/db.ldif.gz');
    lt_msg('krb_principal    = service/ldap');
    lt_msg('krb_realm        = CA-ZEPHYR.ORG');
    lt_msg('krb_tgt          = /run/ldap-acl-access.tgt');
    lt_msg('ldap_base        = dc=ca-zephyr,dc=org');
    lt_msg('ldap_environment = prod');
    lt_msg('ldap_group_base  = cn=groups,dc=ca-zephyr,dc=org');
    lt_msg('ldap_net_base    = cn=net,dc=ca-zephyr,dc=org');
    lt_msg('ldap_host        = localhost');
    lt_msg('#ldap_host       = host1,host2');
    lt_msg('ldap_master_host = ldap-master.ca-zephyr.org');
    lt_msg('# host_prefix = host/');
    lt_msg('# host_prefix = ldap/');
    lt_msg('#');
    lt_msg('# Authentication prefix for remote command execution');
    lt_msg('# krb_prefix = k5start -f /etc/krb5.keytab -U -- ');

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

    my $this_host = lt_pool_host($in{'host'});

    my $ldap;
    if ($in{'debug'}) {
        for my $a (sort keys %in) {
            lt_dbg("in{$a} = $in{$a}");
        }
        lt_dbg("connecting to server " . $this_host);
    }
    if (($ldap = Net::LDAPapi->new($this_host)) == -1) {
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
    if (!$host) {
        my $conf = lt_read_conf();
        $host = $conf->ldap_host();
    }
    @host_list = split(/,/, $host);
    my $idx       = int(rand() * scalar(@host_list));
    my $pool_host = $host_list[$idx];
    $pool_host =~ s/\s+//xmsg;
    return $pool_host;
}

# ------------------------------------------------------------------------
# Read configuration properties

sub lt_read_conf {
    my ($filename) = @_;

    if (!$filename) {
        $filename = '/etc/ldaptools.conf';
    }

    my $conf = AppConfig->new({});
    $conf->define(
        'default_domain',
        {
            DEFAULT  => 'ca-zephyr.org',
            ARGCOUNT => ARGCOUNT_ONE
        }
    );
    $conf->define(
        'dump_db',
        {
            DEFAULT  => '/var/tmp/dbx.ldif.gz',
            ARGCOUNT => ARGCOUNT_ONE
        }
    );
    $conf->define(
        'dump_config',
        {
            DEFAULT  => '/var/tmp/cn-config.ldif',
            ARGCOUNT => ARGCOUNT_ONE
        }
    );
    $conf->define('host_prefix', { ARGCOUNT => ARGCOUNT_LIST });
    $conf->define(
        'krb_keytab',
        {
            DEFAULT  => '/etc/ldap/ldap.keytab',
            ARGCOUNT => ARGCOUNT_ONE
        }
    );
    $conf->define(
        'krb_principal',
        {
            DEFAULT  => 'service/ldap',
            ARGCOUNT => ARGCOUNT_ONE
        }
    );
    $conf->define(
        'krb_tgt',
        {
            DEFAULT  => '/run/ldap-acl-access.tgt',
            ARGCOUNT => ARGCOUNT_ONE
        }
    );
    $conf->define(
        'krb_realm',
        {
            DEFAULT  => 'CA-ZEPHYR.ORG',
            ARGCOUNT => ARGCOUNT_ONE
        }
    );
    $conf->define(
        'ldap_base',
        {
            DEFAULT  => 'dc=ca-zephyr,dc=org',
            ARGCOUNT => ARGCOUNT_ONE
        }
    );
    $conf->define(
        'ldap_environment',
        {
            DEFAULT  => 'prod',
            ARGCOUNT => ARGCOUNT_ONE
        }
    );
    $conf->define(
        'ldap_group_base',
        {
            DEFAULT  => 'cn=groups,dc=ca-zephyr,dc=org',
            ARGCOUNT => ARGCOUNT_ONE
        }
    );
    $conf->define(
        'ldap_net_base',
        {
            DEFAULT  => 'cn=net,dc=ca-zephyr,dc=org',
            ARGCOUNT => ARGCOUNT_ONE
        }
    );
    $conf->define(
        'ldap_host',
        {
            DEFAULT  => 'localhost',
            ARGCOUNT => ARGCOUNT_ONE
        }
    );
    $conf->define(
        'ldap_master_host',
        {
            DEFAULT  => 'ldap-master.ca-zephyr.org',
            ARGCOUNT => ARGCOUNT_ONE
        }
    );
    $conf->define(
        'ldap_service_base',
        {
            DEFAULT  => 'cn=services,dc=ca-zephyr,dc=org',
            ARGCOUNT => ARGCOUNT_ONE
        }
    );
    $conf->define(
        'remctl_group_command',
        {
            DEFAULT  => 'group',
            ARGCOUNT => ARGCOUNT_ONE
        }
    );
    $conf->define('krb_prefix', { ARGCOUNT => ARGCOUNT_ONE });

    if (-e $filename) {
        $conf->file($filename) or die "ERROR: problem reading $filename";
    }

    return $conf;
}

# Run a shell command carefully

sub _set_path {
    print('PATH=/bin:/sbin:/usr/bin:/usr/sbin ');
}

sub lt_run_cmd {
    my @cmd = @_;

    lt_msg('running command:' . join(q{ }, @cmd));

    my $in;
    my $out;
    my $err;
    eval { IPC::Run::run(\@cmd, \$in, \$out, \$err, init => \&_set_path); };
    if ($@ || $err) {
        lt_msg('ERROR: Problem executing:' . join(q{ }, @cmd));
        lt_msg($@);
        lt_msg('Returned error: ' . $err);
        die "Execution abandoned\n";
    }
    lt_msg($out);
    return;
}

END { }

1;

=head1 NAME

CZ::LDAPtools - Utility routines for the LDAP Servers

=head1 SYNOPSIS

    use CZ::LDAPtools;

    $CONF = lt_read_conf('/etc/ldaptools.conf');

    $DIR = lt_ldap_connect (host      => 'host1,host2,host3',
                            principal => 'service/name',
                            keytab    => '/etc/ldap/ldap-admin.keytab',
                            tgt       => '/run/ldap-server.tgt',
                            anonymous => 'anyvalue',
                            debug     => 'anyvalue');
    lt_ldap_disconnect ($DIR);

    lt_dbg('some message');

    lt_msg('some text');

    lt_example_conf();

    my $acl = lt_format_acls($<acl string>);

    $ldap_hostname = lt_pool_host('host1,host2,host3');

=head1 DESCRIPTION

This module holds common routines used by perl scripts when accessing
LDAP servers.

=head1 FUNCTIONS

=over 4

=item lt_dbg

Displays the message passed as parameter with the prefix 'DEBUG:'.

=item lt_example_conf

Display an example configuration file.

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

=item lt_read_conf

Reads the ldaptools configuration file. The default file,
/etc/ldaptools.conf, can be overridden by passed the conf file to the
routine as the only parameter.

=back

=head1 BACKWARDS COMPATIBILITY

With version 3 of LDAPtools the routines were renamed to prevent name
collisions. The old routine names are preserved, but are depricated.
The mapping of old names to new names is:

    read_ldap_tools_conf -> lt_read_conf
    format_acls          -> lt_format_acls
    ldap_connect         -> lt_ldap_connect
    ldap_disconnect      -> lt_ldap_disconnect

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
