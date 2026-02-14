using System;
using System.Collections.Generic;
using System.Diagnostics;

namespace ValvePak
{
	sealed class CaseInsensitivePackageEntryComparer(StringComparison comparison) : IComparer<PackageEntry>
	{
		public StringComparison Comparison { get; } = comparison;

		/// <remarks>
		/// Intentionally not comparing <see cref="PackageEntry.TypeName"/> because this comparer is used on <see cref="Package.Entries"/> which is split by extension already.
		/// </remarks>
		public int Compare(PackageEntry? x, PackageEntry? y)
		{
			if (x == null) throw new ArgumentNullException(nameof(x));
			if (y == null) throw new ArgumentNullException(nameof(y));

			var comp = x.FileName.Length.CompareTo(y.FileName.Length);
			if (comp != 0) return comp;

			comp = x.DirectoryName.Length.CompareTo(y.DirectoryName.Length);
			if (comp != 0) return comp;

			comp = string.Compare(x.FileName, y.FileName, Comparison);
			if (comp != 0) return comp;

			return string.Compare(x.DirectoryName, y.DirectoryName, Comparison);
		}

	}
}
