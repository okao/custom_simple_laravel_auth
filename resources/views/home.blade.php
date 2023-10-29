<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <meta http-equiv="X-UA-Compatible" content="ie=edge">

    {{-- tailwindcss cdn --}}
    <script src="https://cdn.tailwindcss.com"></script>

    {{-- jquery 3.2 cdn --}}
    <script src="https://cdnjs.cloudflare.com/ajax/libs/jquery/3.2.1/jquery.min.js"></script>
    <title>Home</title>
</head>
<body>
    {{-- i want a nice home page here which says welcome with username --}}
    <div class="flex flex-col items-center justify-center min-h-screen bg-cover bg-center bg-gray-100">
        <div class="w-full max-w-md">
            <div class="bg-white rounded-lg shadow-lg p-8">
            <div class="flex justify-center">
                <img class="h-36 w-36" src="https://d1csarkz8obe9u.cloudfront.net/posterpreviews/company-logo-design-template-e089327a5c476ce5c70c74f7359c5898_screen.jpg?ts=1672291305" alt="Logo">
            </div>
                <div class="mt-8">
                    <h1 class="text-2xl font-bold text-center">Welcome {{ $user->username }}</h1>
                </div>

                <div class="mt-8 w-full mt-10">
                    {{-- form to submit logout --}}
                    <form id="logout-form" action="{{ route('logout_api') }}" method="POST" class="hidden">
                        @csrf
                    </form>

                    {{-- logout button --}}
                    <button onclick="event.preventDefault(); document.getElementById('logout-form').submit();" class="bg-blue-500 hover:bg-blue-700 text-white font-bold py-2 px-4 rounded focus:outline-none focus:shadow-outline w-full" type="button">
                        Logout from here
                    </button>

                </div>
            </div>
        </div>
    </div>
</body>
</html>
