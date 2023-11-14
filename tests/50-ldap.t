#!/usr/bin/perl -w
#
# tests/50-ldap.t

use Carp;
use Getopt::Long;
use IPC::Run qw( start pump finish run timeout );
use strict;
use Test::More qw( no_plan );

my $opt_debug;
my $opt_disable;

my $DIR_ROOT    = '../tmp/test-slapd';
my $DIR_CONFIG  = "$DIR_ROOT/slapd.d";
my $DIR_DB      = "$DIR_ROOT/db";
my $FILE_ARGS   = "$DIR_ROOT/slapd.args";
my $FILE_PID    = "$DIR_ROOT/slapd.pid";
my $LDAP_BASE   = 'dc=ca-zephyr,dc=org';
my $LDIF_CONFIG = "$DIR_ROOT/cn-config.ldif";
my $LDIF_DB     = "$DIR_ROOT/db.ldif";
my $URI         = 'ldap://127.0.0.1:9000/';

my @ERR_STRS = ['Traceback', 'ERROR:'];

my $LDAP_DUMPED;

#########################################################################
# Subroutines
#########################################################################

# -----------------------------------------------------------------------
# print error returns with delimiters to make them more visible

sub print_err {
    my ($test, $err) = @_;

    my $txt = "Unexpected output from $test ";
    my $sz  = 72 - length($txt);
    if ($sz < 5) {
        $sz = 5;
    }
    my $hdr = $txt . '=' x $sz;

    fail($test);
    print("$hdr\n");
    print("$err\n");
    print('=' x 72 . "\n");

    if (!$LDAP_DUMPED) {
        print(search_ldap_db());
        print('=' x 72 . "\n");
        $LDAP_DUMPED = 1;
    }

    return;
}

# -----------------------------------------------------------------------
# read file

sub read_file {
    my ($path) = @_;
    if (!-e $path) {
        croak "ERROR: file not found $path\n";
    }
    open(my $fd, '<', $path) or croak "ERROR: openingfile $path\n";
    my $s;
    while (<$fd>) {
        $s .= $_;
    }
    close $fd or croak "ERROR: closing file $path\n";
    return $s;
}

# -----------------------------------------------------------------------
# run a shell command line

sub run_cmd {
    my @cmd = @_;

    my $return_text = '';
    my $in;
    my $out;
    my $err;
    if ($opt_debug) {
        print "\n";
        print "Executing: " . join(' ', @cmd) . "\n";
    }
    eval { run(\@cmd, \$in, \$out, \$err, timeout(30)); };
    if ($@) {
        if ($err) {
            $err .= "\n";
        }
        $err .= 'ERROR executing:' . join(q{ }, @cmd) . "\n";
        $err .= $@;
        croak "$err\n";
    }
    if ($out) {
        $return_text .= "$out\n";
    }
    if ($err) {
        $return_text .= "ERROR: $err\n";
    }
    return $return_text;
}

# ------------------------------------------------------------------------
# Create the LDAP configuration file

sub create_config {
    open(my $fd, '>', $LDIF_CONFIG)
      or croak "ERROR: writing to $LDIF_CONFIG\n";

    my $header = read_file('data/config_header.ldif');
    $header =~ s/testPIDFILEtest/$FILE_PID/xms;
    $header =~ s/testARGStest/$FILE_ARGS/xms;

    my $footer = read_file('data/config_footer.ldif');
    $footer =~ s/testDBDIRtest/$DIR_DB/xms;

    print $fd $header . "\n";
    print $fd read_file('data/schema_core.ldif') . "\n";
    print $fd read_file('data/schema_cosine.ldif') . "\n";
    print $fd read_file('data/schema_nis.ldif') . "\n";
    print $fd read_file('data/schema_inetorgperson.ldif') . "\n";
    print $fd read_file('data/schema_misc.ldif') . "\n";
    print $fd read_file('data/schema_krb5_kdc.ldif') . "\n";
    print $fd read_file('data/schema_pdns.ldif') . "\n";
    print $fd $footer . "\n";
    close $fd or croak "ERROR: closing $LDIF_CONFIG\n";

    return;
}

# ------------------------------------------------------------------------
# Create the inital LDAP database

sub create_db {
    my $db = read_file('data/ldap_db.ldif');
    open(my $fd, '>', $LDIF_DB) or croak "ERROR: opening $LDIF_DB\n";
    print $fd $db;
    close $fd or croak "ERROR: closing $LDIF_DB\n";;
    return;
}

# ------------------------------------------------------------------------
# Clean out old directories if they exists and then create a new
# empty directories.

sub create_dirs {
    if (-e $DIR_ROOT) {
        system("rm -rf $DIR_ROOT");
    }
    for my $d ($DIR_CONFIG, $DIR_DB) {
        system("mkdir -p $d");
    }
    return;
}

# ------------------------------------------------------------------------
# Check return from a test for forbidden strings
# Parameters:
#      parameter 1 = $t_name, the test name
#      parameter 2 = reference to command array
#      parameter 3 = $t_out, the test output
#      parameter 4 = reference to array of strings that must be missing

sub check_missing {
    my ($t_name, $t_cmd_ref, $t_out, $t_strs_ref) = @_;
    my @cmd  = @{$t_cmd_ref};
    my @strs = @{$t_strs_ref};
    if (!$t_out) {
        print_err($t_name, 'No output from command');
    } else {
        my $err;
        for my $s (@strs) {
            if ($t_out =~ /$s/ms) {
                $err .= "ERROR: Found $s\n";
            }
        }
        if ($err) {
            my $msg;
            my $this_cmd = join(' ', @cmd);
            $msg .= "EXECUTING: $this_cmd\n";
            $msg .= "OUTPUT:\n";
            $msg .= $t_out . "\n";
            $msg .= ('=' x 72)  . "\n";
            $msg .= "ERROR:\n";
            $msg .= $err;
            print_err($t_name, $msg);
        } else {
            pass($t_name);
        }
    }
    return;
}

# ------------------------------------------------------------------------
# Check return from a test using a full regex.
# Parameters:
#      parameter 1 = $t_name, the test name
#      parameter 2 = reference to command array
#      parameter 3 = $t_out, the test output
#      parameter 4 = reference to regex's to search for in the output
#      parameter 5 = reference to array of strings that must not appear
#                    in the output.  The default is 'Traceback'.

sub check_output_regex {
    my ($t_name, $t_cmd_ref, $t_out, $t_strs_ref, $t_miss_ref) = @_;
    my @cmd  = @{$t_cmd_ref};
    my @strs = @{$t_strs_ref};
    my @miss;
    if ($t_miss_ref) {
        @miss = @{$t_miss_ref};
        if ($miss[0] eq 'NONE') {
            @miss = ();
        }
    } else {
        @miss = ('Traceback');
    }

    if (!$t_out) {
        print_err($t_name, 'No output from command');
    } else {
        my $err;
        for my $s (@strs) {
            my $rex = $s;
            $rex =~ s{([()*&-])}{\\$1}xmsg;
            if ($t_out !~ /$rex/xms) {
                $err .= "MISSING REGEX: $rex\n";
            }
        }
        for my $m (@miss) {
            if ($t_out =~ /$m/ms) {
                $err .= "ERROR: Found $m\n";
            }
        }

        if ($err) {
            my $msg;
            my $this_cmd = join(' ', @cmd);
            $msg .= "EXECUTING: $this_cmd\n";
            $msg .= "OUTPUT:\n";
            $msg .= $t_out . "\n";
            $msg .= ('=' x 72) . "\n";
            $msg .= "ERROR:\n";
            $msg .= $err;
            print_err($t_name, $msg);
        } else {
            pass($t_name);
        }
    }
    return;
}

# ------------------------------------------------------------------------
# Dump the LDAP database

sub search_ldap_db {
    my ($filter) = @_;
    my @cmd_search = ('/usr/bin/ldapsearch',
                      '-x', '-LLL',
                      '-H', $URI,
                      '-o', 'ldif-wrap=no',
                      '-b', 'dc=ca-zephyr,dc=org');
    if ($filter) {
        push(@cmd_search, $filter);
    }
    return run_cmd(@cmd_search);
}

#########################################################################
# Main Routine
#########################################################################

# Debugging option
GetOptions(
    'debug'   => \$opt_debug,
    'disable' => \$opt_disable
);

if ($opt_disable) {
    pass('All tests with an LDAP server disabled');
    exit;
}

# ------------------------------------------------------------------------
# Create test directory
create_dirs();

# Create the LDAP configuation and add it to the slapd instance
create_config();
my @cmd_config = ('/usr/sbin/slapadd',
          '-b', 'cn=config',
          '-F', $DIR_CONFIG,
          '-l', $LDIF_CONFIG);
my $config_output = run_cmd(@cmd_config);
if ($config_output) {
    print("CONFIG load:\n$config_output");
} else {
    if ($opt_debug) {
        print("No output from $LDIF_CONFIG load\n");
    }
}

# Create the top of the directory tree
create_db();
my @cmd_db = ('/usr/sbin/slapadd',
          '-b', $LDAP_BASE,
          '-F', $DIR_CONFIG,
          '-l', $LDIF_DB);
my $db_output = run_cmd(@cmd_db);
if ($db_output) {
    print("DB load:\n$db_output");
} else {
    if ($opt_debug) {
        print("No output from $LDIF_DB load\n");
    }
}

# ------------------------------------------------------------------------
# Start slapd server to use for testing
my $slapd_cmd = "/usr/sbin/slapd -F $DIR_CONFIG -h $URI";
if ($opt_debug) {
    print "\n";
    print "Executing: $slapd_cmd\n";
}
system($slapd_cmd);
sleep 1;

my @t_cmd = ();
my $t_filter;
my $t_name;
my $t_out;
my $t_site_dn;
my @t_strs = ();

# ------------------------------------------------------------------------
# Just test to make sure we can talk to the ldap server

$t_name = 'Initial slapd test';
@t_cmd = ('search database');
$t_out  = search_ldap_db();
@t_strs = (
    'dn:\s+ dc=ca-zephyr,dc=org',
    'dn:\s+ ou=net,dc=ca-zephyr,dc=org',
    );
check_output_regex($t_name, \@t_cmd, $t_out, \@t_strs);

##############################################################################
# Tests
##############################################################################

$t_name = 'Simple bind - no dn or pw';
@t_cmd = ('perl', '-I', '../usr/share/perl5', 'scripts/simple.pl',
          'nodn');
$t_out = run_cmd(@t_cmd);
@t_strs = (
    'ERROR:\s+ missing\s+ parameter\s+ user_dn',
    );
check_output_regex($t_name, \@t_cmd, $t_out, \@t_strs);

$t_name = 'Simple bind';
@t_cmd = ('perl', '-I', '../usr/share/perl5', 'scripts/simple.pl',
          'bind', 'cn=manager,dc=ca-zephyr,dc=org', 'secret');
$t_out = run_cmd(@t_cmd);
@t_strs = (
    'Simple\s+ bind\s+ complete',
    );
check_output_regex($t_name, \@t_cmd, $t_out, \@t_strs);

$t_name = 'Search';
@t_cmd = ('perl', '-I', '../usr/share/perl5', 'scripts/simple.pl',
          'search', 'cn=manager,dc=ca-zephyr,dc=org', 'secret');
$t_out = run_cmd(@t_cmd);
@t_strs = (
    'DN:\s+ dc=internal,ou=net,dc=ca-zephyr,dc=org',
    'associatedDomain:\s+ internal',
    'DN:\s+ dc=org,ou=net,dc=ca-zephyr,dc=org',
    'associatedDomain:\s+ org',
    );
check_output_regex($t_name, \@t_cmd, $t_out, \@t_strs);

# ----------------------------------------------------------------------
# Debugging display of ldap directory contents
if ($opt_debug) {
    $t_name = 'Debugging display of directory entries';
    $t_out = search_ldap_db();
    if (!$t_out) {
        print_err($t_name, 'No output from command');
    } else {
        print($t_out);
    }
}

# ----------------------------------------------------------------------
# Kill off the background slapd process.
if (!-e $FILE_PID) {
    print("ERROR: file not found $FILE_PID\n");
} else {
    system("kill -9 `cat $FILE_PID`");
}

exit 0;
