# Theowall


La aplicación Theowall es un gestor de contraseñas. Permite poder guardar las credenciales del usuario de cualquier red social, página web, aplicación de forma segura, facilitando que el usuario pueda poner contraseñas más y complejas seguras sin miedo a que se le olviden.

Por el momento el usuario puede registrarse, acceder a la aplicación, crear credenciales, modificar credenciales, eliminar credenciales y modificar los datos de perfil del usuario.

La aplicación funciona con una base de datos con archivo .json. En dicho archivo se guardan los datos del perfil de usuario junto con el hash de la contraseña de acceso a la app y el contenido (las credenciales) cifrado al cual solo el usuario puede acceder con su contraseña maestra (la contraseña de acceso a la aplicación).

Además, la aplicación cuenta con un generador de documentos. Dichos documentos contienen las credenciales del usuario solicitante. Este documento está firmado por la aplicación. Esta firma se puede verificar desde la propia aplicación.
