@extends('auth.layout')

@section('content')
    <div class="flex flex-col items-center justify-center min-h-screen bg-cover bg-center bg-gray-100">
        <div class="w-full max-w-md">
            <div class="bg-white rounded-lg shadow-lg p-8">
            <div class="flex justify-center">
                <img class="h-36 w-36" src="https://d1csarkz8obe9u.cloudfront.net/posterpreviews/company-logo-design-template-e089327a5c476ce5c70c74f7359c5898_screen.jpg?ts=1672291305" alt="Logo">
            </div>

            {{-- error and succsss session messages --}}
            @if (session('error'))
                <div class="bg-red-100 border border-red-400 text-red-700 px-4 py-3 rounded relative my-4" role="alert">
                    <strong class="font-bold">Error!</strong>
                    <span class="block sm:inline">{{ session('error') }}</span>
                </div>
            @endif

            @if (session('success'))
                <div class="bg-green-100 border border-green-400 text-green-700 px-4 py-3 rounded relative my-4" role="alert">
                    <strong class="font-bold">Success!</strong>
                    <span class="block sm:inline">{{ session('success') }}</span>
                </div>
            @endif

            <form class="mt-8" method="POST" action="{{ route('submit_login') }}">
                @csrf
                <div>
                    <label class="block text-gray-700 font-bold mb-2" for="username">
                        Username
                    </label>
                    <input name="username" class="appearance-none border rounded w-full py-2 px-3 text-gray-700 leading-tight focus:outline-none focus:shadow-outline" id="username" type="text" placeholder="Username">
                    </div>
                    <div class="mt-4">
                    <label class="block text-gray-700 font-bold mb-2" for="password">
                        Password
                    </label>
                    <input name="password" type="password" class="appearance-none border rounded w-full py-2 px-3 text-gray-700 leading-tight focus:outline-none focus:shadow-outline" id="password" type="password" placeholder="Password">
                    </div>
                    <div class="mt-8">
                    <button type="submit" class="w-full bg-blue-500 hover:bg-blue-700 text-white font-bold py-2 px-4 rounded focus:outline-none focus:shadow-outline" type="button">
                        Sign In
                    </button>
                </div>
            </form>
            </div>
        </div>
    </div>
@endsection
