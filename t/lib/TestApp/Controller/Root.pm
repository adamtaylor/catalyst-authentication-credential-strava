package TestApp::Controller::Root;
 
use Moose;
use namespace::autoclean;
 
BEGIN { extends 'Catalyst::Controller' }
 
__PACKAGE__->config(namespace => '');
 
sub auth : Local {
    my ($self, $c) = @_;
 
    my $user = $c->authenticate();
 
    $c->detach unless $user;
 
    $c->response->body('success');
}
 
__PACKAGE__->meta->make_immutable;
 
1;
