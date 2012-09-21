package Digest::ED2K;
use base qw(Digest::base);
use common::sense;
use Digest::MD4;
use Exporter 'import';
our @EXPORT_OK = qw(ed2k ed2k_hex ed2k_base64);
use version 0.77; our $VERSION = version->declare('v1.0');

use constant CHUNK_SIZE => 9728000;

sub new {
	my $class = shift;
	bless {
		ctx => Digest::MD4->new,
		blocks => 0,
		buffer => '',
		_digest => undef,
	}, ref($class) || $class;
}

sub clone {
	my $self = shift;
	bless {
		ctx => $self->{ctx}->clone,
		blocks => $self->{blocks},
		buffer => $self->{buffer},
		_digest => $self->{_digest},
	}, ref($self);
}

sub add {
	my $self = shift;
	if(defined $self->{_digest}) {
		require Carp;
		Carp::croak("Can't add to a ed2k digest after it's been finalized. Please reset the object if you wish to reuse it.");
	}
	$self->{buffer} .= join '', @_;
	while(length($self->{buffer}) >= CHUNK_SIZE) {
		$self->{ctx}->add(Digest::MD4->new->add(substr($self->{buffer}, 0, CHUNK_SIZE))->digest);
		$self->{buffer} = substr($self->{buffer}, CHUNK_SIZE);
		$self->{blocks}++;
	}
	$self;
}

sub digest {
	my $self = shift;
	return $self->{_digest} if defined $self->{_digest};
	if(!$self->{blocks}) {
		$self->{_digest} = Digest::MD4->new->add($self->{buffer})->digest;
	}
	else {
		$self->{ctx}->add(Digest::MD4->new->add($self->{buffer})->digest);
		$self->{buffer} = '';
		$self->{_digest} = $self->{ctx}->digest;
	}
	return $self->{_digest};
}

sub ed2k(@) {
	Digest::ED2K->new->add(@_)->digest;
}

sub ed2k_hex(@) {
	Digest::ED2K->new->add(@_)->hexdigest;
}

sub ed2k_base64(@) {
	Digest::ED2K->new->add(@_)->b64digest;
}

0x6B63;
__END__

=head1 NAME

Digest::ED2K - Calculate ED2K digests

=head1 SYNOPSIS

	# Functional
	use Digest::ED2K qw(ed2k ed2k_hex ed2k_base64);

	my $digest = ed2k $data;
	my $hexdigest = ed2k_hex $data
	my $base64_digest = ed2k_base64 $data;

	# Object Oriented
	use Digest::ED2K;

	my $ctx = Digest::ED2K->new;

	$ctx->add($bytes);
	$ctx->addfile(*FILE);

	my $digest = $ctx->digest;
	my $hexdigest = $ctx->hexdigest;
	my $base64_digest = $ctx->b64digest;

=head1 DESCRIPTION

L<Digest::ED2K> progressively calculates ED2K digests of data.

=head1 FUNCTIONS

L<Digest::ED2K> implements the following functions.

=head2 C<ed2k>

	my $digest = ed2k $bytes, ...;

Generate binary ED2K digest for string.

=head2 C<ed2k_hex>

	my $hexdigest = ed2k_hex $bytes, ...;

Generate hex ED2K digest for string.

=head2 C<ed2k_base64>

	my $base64_digest = ed2k_base64 $bytes, ...;

Generate base64 ED2K digest for string.

=head1 METHODS

L<Digest::ED2K> inherits all methods from L<Digest::base> (See L<Digest> for
documentation) and implements the following new ones.

=head2 C<new>

	my $ctx = Digest->new('ED2K');
	my $ctx = Digest::ED2K->new;

Construct a new L<Digest::ED2K> object.

=head2 C<add>

	$ctx = $ctx->add($bytes, ...);

Append binary data.

=head2 C<clone>

	my $ctx_clone = $ctx->clone;

Clone this message context.

=head2 C<digest>

	my $digest = $ctx->digest;

Binary ED2K digest for this message context.

=head1 SEE ALSO

L<Digest>, L<Digest::MD4>

=head1 AUTHOR

Benjamin Herweyer <benjamin.herweyer@gmail.com>

=head1 COPYRIGHT AND LICENSE

Copyright 2011 by Benjamin Herweyer

Permission to use, copy, modify, and/or distribute this software for any
purpose with or without fee is hereby granted, provided that the above
copyright notice and this permission notice appear in all copies.

THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.

=head1 REPOSITORY

http://github.com/Kulag/Digest-ED2K
