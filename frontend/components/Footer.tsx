export default function Footer() {
  return (
    <footer className="bg-white border-t border-gray-200 mt-auto">
      <div className="max-w-7xl mx-auto py-6 px-4 sm:px-6 lg:px-8">
        <p className="text-center text-sm text-gray-600">
          MySSO - Système d'authentification créé par{' '}
          <span className="font-semibold text-indigo-600">Louis BERTRAND</span>
        </p>
        <p className="text-center text-xs text-gray-500 mt-2">
          Ce service d'authentification unique (SSO) permet de s'authentifier de manière centralisée sur toutes mes futures applications
        </p>
      </div>
    </footer>
  );
}
