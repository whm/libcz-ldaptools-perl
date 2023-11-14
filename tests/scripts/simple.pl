#!/usr/bin/perl

use strict;
use CZ::LDAPtools;
use Net::LDAPapi;

my $LDAP_HOST = '127.0.0.1';
my $LDAP_PORT = 9000;
my $LDAP;

##############################################################################
# subroutines
##############################################################################

sub do_bind {
    my ($dn, $pw) = @_;
    $LDAP = lt_ldap_connect(
        {
            host     => $LDAP_HOST,
            port     => $LDAP_PORT,
            bindtype => 'simple',
            user_dn  => $dn,
            user_pw  => $pw,
            debug    => 1,
        }
        );
    return;
}

my $action = shift;

if ($action eq 'nodn') {
    $LDAP = lt_ldap_connect(
        {
            host     => $LDAP_HOST,
            port     => $LDAP_PORT,
            bindtype => 'simple',
            debug    => 1,
        }
        );
} elsif ($action eq 'bind') {
    my $dn = shift;
    my $pw = shift;
    do_bind($dn, $pw);
    print("Simple bind complete\n");
} elsif ($action eq 'search') {
    my $dn = shift;
    my $pw = shift;
    do_bind($dn, $pw);
    my $base   = 'dc=ca-zephyr,dc=org';
    my $filter = '(objectClass=PdnsRecordData)';
    my $msg = $LDAP->search_s(
        -basedn    => $base,
        -scope     => LDAP_SCOPE_SUBTREE,
        -filter    => $filter,
        -attrs     => ['associatedDomain', 'aRecord'],
        -attrsonly => 0,
    );
    if ($LDAP->errno != 0) {
        print('errno: ' . $LDAP->errno . "\n");
        $LDAP->perror(
            "ERROR: problem searching using base:$base filter:$filter\n");
        exit 1;
    }
    my %entries = %{ $LDAP->get_all_entries };
    for my $dn (keys %entries) {
        print("DN: $dn\n");
        for my $attr (sort keys %{ $entries{$dn} }) {
            for my $val (@{ $entries{$dn}{$attr} }) {
                print("$attr: $val\n");
            }
        }
        print("\n");
    }
} else {
    print("ERROR: unknown action $action\n");
    exit 1;
}

$LDAP->unbind;

exit;
