package Lemonldap::Crypto;

use strict;
use Crypt::CBC;
use MIME::Base64;
use Digest::MD5 qw(md5);

our @ISA = qw(Crypt::CBC);

our $VERSION = '0.01';

# Preloaded methods go here.
sub sign($$) {
	my($self,$text) = @_;
	my $return = encode_base64($self->encrypt(md5($text)));
	$return =~ s/( |\n)//g;
	$return =~ s/\+/_/g;
	print STDERR "DEBUG: $return\n";
	return $return;
}
sub sign_verify {
	my($self,$text,$sign) = @_;
	$sign =~ s/_/\+/g;
	return ($self->decrypt(decode_base64($sign)) eq md5($text));
}

1;
__END__
# Below is stub documentation for your module. You'd better edit it!

=head1 NAME

Lemonldap::Crypto - Perl extension written to implement a little signature
mechanism.

=head1 SYNOPSIS

  use Lemonldap::Crypto;
  my $cr = new Lemonldap::Crypto (
        key    => 'my key',
        cipher => 'blowfish'
	);
  my $sign = $cr->sign($text);
  ...
  die "Invalid signature" unless ($cr->sign_verify($text,$sign));

See Crypt::CBC for more options.

=head1 DESCRIPTION

Lemonldap::Crypto extends Crypt::CBC and adds two subroutine (sign and
sign_verify). This mechanism is used by Lemonldap to secure handler/manager
channel.

=head2 EXPORT

None by default.

=head1 SEE ALSO

=over 1

=item Crypt::CBC(3)

=item http://lemonldap.sourceforge.net/

=back

=head1 AUTHOR

Xavier Guimard, E<lt>x.guimard@free.frE<gt>

=head1 COPYRIGHT AND LICENSE

Copyright (C) 2004 by Xavier Guimard

This library is free software; you can redistribute it and/or modify
it under the same terms as Perl itself, either Perl version 5.8.4 or,
at your option, any later version of Perl 5 you may have available.

=cut
