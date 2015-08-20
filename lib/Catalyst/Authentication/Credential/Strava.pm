# ABSTRACT: Catalyst Authentication using Strava
package Catalyst::Authentication::Credential::Strava;

# VERSION

=head1 SYNOPSIS

    package MyApp;

    __PACKAGE__->config(
        'Plugin::Authentication' => {
            default => {
                credential => {
                    class         => 'Strava',
                    client_id     => $client_id,
                    client_secret => $client_secret,
                },
                store => {
                    ...
                },
            },
        },
    );

    package MyApp::Controller::Login;

    sub login : Local {
        my ( $self, $c ) = @_;

        # Redirects to Strava for the user to login and authorise the application.
        # Uses the returned access token to lookup a user in the store.
        my $user = $c->authenticate();

        $c->detach unless $user;

        # Do any post login actions you like
    }

=head1 DESCRIPTION

Authenticate your Catalyst application's users using L<Strava's OAuth API|https://www.strava.com/developers>.

=head1 ATTRIBUTES

=head2 C<client_id>

This is provided by Strava's API when you register your application with their API.

=head2 C<client_secret>

This is provided by Strava's API when you register your application with their API

=head1 METHODS

=head2 C<authenticate>

    my $user = $c->authenticate();

Attempts to authenticate a user using Strava's OAuth API. Because this is an OAuth
authentication provider this will cause a redirect to the Strava website, where
the user can login or register, which will then redirect back to your Catalyst
application with an access token.

This token (C<strava_access_token>) is used to look up a user and return one, if
found, or undef. An exception is thrown if the access token retreival fails.

If you just want to retrieve the token, you should look at
L<Catalyst::Authentication::Store::Null> otherwise if you use something like
L<Catalyst::Authentication::Store::DBIx::CLass> your user table shold have a column
C<strava_access_token> for user lookup.

=head1 CUSTOMISATION

If you want to customise the behavior of this module, please take a look at
L<Catalyst::Authentication::Realm::Adaptor>.

=head1 ACKNOWLEDGEMENTS

This is basically L<Catalyst::Authentication::Credential::Facebook::OAuth2> made
to work with Strava with the help of L<LWP::Authen::OAuth2>.

=cut

use Moose;
use namespace::autoclean;

use JSON::XS;
use LWP::Authen::OAuth2;

has 'client_id' => (
    isa => 'Str',
    is => 'ro',
);

has 'client_secret' => (
    isa => 'Str',
    is => 'ro',
);

has 'client' => (
    isa => 'LWP::Authen::OAuth2',
    is => 'rw',
);

sub BUILDARGS {
    my ($self, $config, $ctx, $realm) = @_;

    return $config;
}

sub _build_client {
    my ( $self, @args ) = @_;

    my %build_args = (
        service_provider => 'Strava',
        client_id => $self->client_id,
        client_secret => $self->client_secret,
    );

    return LWP::Authen::OAuth2->new(%build_args,@args);
}

sub authenticate {
    my ($self, $c, $realm, $auth_info) = @_;

    my $callback_uri = $c->request->uri->clone;
    $callback_uri->query(undef);

    my $client = $self->_build_client(
        redirect_uri => $callback_uri,
    );

    $self->client( $client );

    # No callback yet, setup the authentication
    unless ( defined( my $code = $c->request->params->{code} ) ) {
        $c->response->redirect( $self->client->authorization_url );
    }
    # We're in the callback
    else {
        $self->client->request_tokens( code => $code );
        my $token_string = decode_json $self->client->token_string;

        die 'Error validating verification code' unless $token_string;

        my $user = $realm->find_user({
            strava_access_token => $token_string->{access_token},
        }, $c );

        return $user;
    }

}

__PACKAGE__->meta->make_immutable;

1;
