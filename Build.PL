#! /usr/bin/env perl

use strict;
use warnings;

use Module::Build 0.3601;

my %module_build_args = (
	module_name   => 'Digest::ED2K',
	create_readme => 1,
	license       => 'isc',
	build_requires => {
		'Test::More'     => 0,
	},
	requires      => {
		'perl'           => '5.08.0',
		'base'           => '0',
		'Carp'           => '0',
		'common::sense'  => '0',
		'Digest::MD4'    => '0',
		'version'        => '0.77',
	},
);

my $build = Module::Build->new(%module_build_args);

$build->create_build_script;
