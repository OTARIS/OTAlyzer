using System;
using System.Runtime.CompilerServices;

namespace OTAlyzer.Common
{
    public static class Logger
    {
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public static void Log(string message)
        {
            Console.WriteLine($"    {message}");
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public static void LogAlert(string message)
        {
            CwColored($"[!] {message}", ConsoleColor.DarkYellow);
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public static void LogPositive(string message)
        {
            CwColored($"[+] {message}", ConsoleColor.DarkGreen);
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public static void LogNegative(string message)
        {
            CwColored($"[-] {message}", ConsoleColor.DarkRed);
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        private static void CwColored(string message, ConsoleColor color)
        {
            Console.ForegroundColor = color;
            Console.WriteLine($"{message}");
            Console.ResetColor();
        }
    }
}