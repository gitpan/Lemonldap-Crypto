# Before `make install' is performed this script should be runnable with
# `make test'. After `make install' it should work as `perl Lemonldap-Crypto.t'

#########################

use Test::Simple tests => 2;
use Lemonldap::Crypto;

#########################

my $text="Test text";
my $cr = new Lemonldap::Crypto ( {key => 'My Key', cipher => $algo} );
ok( defined $cr );
ok( $cr->sign_verify($text, $cr->sign($text)) );
