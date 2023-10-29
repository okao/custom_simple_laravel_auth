@extends('auth.layout')

@section('content')
    <div class="flex flex-col items-center justify-center min-h-screen bg-cover bg-center bg-gray-100">
        <div class="w-full max-w-md">
            <div class="bg-white rounded-lg shadow-lg p-8">
            <div class="flex justify-center">
                <img class="h-36 w-36" src="https://d1csarkz8obe9u.cloudfront.net/posterpreviews/company-logo-design-template-e089327a5c476ce5c70c74f7359c5898_screen.jpg?ts=1672291305" alt="Logo">
            </div>

            {{-- session success message --}}
            @if (session('success'))
                <div class="bg-green-100 border border-green-400 text-green-700 px-4 py-3 rounded relative my-4" role="alert">
                    <strong class="font-bold">Success!</strong>
                    <span class="block sm:inline">{{ session('success') }}</span>
                </div>
            @endif

            {{-- session error message --}}
            @if (session('error'))
                <div class="bg-red-100 border border-red-400 text-red-700 px-4 py-3 rounded relative my-4" role="alert">
                    <strong class="font-bold">Error!</strong>
                    <span class="block sm:inline">{{ session('error') }}</span>
                </div>
            @endif

            <form class="mt-8" method="POST" action="{{ route('submit_consent') }}">
                @csrf
                <div>
                    {{-- i agree to allow this and that to this app --}}
                    <label class="block text-gray-700 font-bold mb-2" for="code">
                        I agree to allow this for the following:
                    </label>

                    {{-- list of access --}}
                    <ul class="list-disc list-inside">
                        <li>Access your profile</li>
                        <li>Access your posts</li>
                        <li>Access your friends</li>
                    </ul>

                    {{-- submit button --}}
                    <div class="mt-8">
                        <button type="submit" class="w-full bg-blue-500 hover:bg-blue-700 text-white font-bold py-2 px-4 rounded focus:outline-none focus:shadow-outline" type="button">
                            I Agree
                        </button>
                    </div>
                </div>
            </form>
            </div>
        </div>
    </div>
@endsection
